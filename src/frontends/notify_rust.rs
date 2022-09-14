//! A front-end using the [notify-rust crate](https://crates.io/crates/notify-rust).

use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};

use log::error;
use notify_rust::{
    get_capabilities, get_server_information, Notification, NotificationHandle, Timeout,
};
use url::Url;

use super::Frontend;

const NOTIFICATION_TIMEOUT: u64 = 30; // Seconds

/// A frontend using the `notify-rust` library. We spin up a thread which listens for
/// authentication URL requests/success/failure, and shows/updates/closes a notification as
/// appropriate.
pub struct NotifyRust {
    auth_pred: Mutex<bool>,
    auth_condvar: Condvar,
    /// Queued authentication URLs. A `None` URL means "this account has now authenticated and it
    /// no longer needs to be displayed to the user."
    auth_urls: Mutex<HashMap<String, Option<Url>>>,
}

impl Frontend for NotifyRust {
    fn new() -> Result<Self, Box<dyn Error>> {
        let caps = get_capabilities()?;
        let mut missing = Vec::new();
        for c in ["body", "body-hyperlinks", "body-markup"] {
            if !caps.contains(&c.to_owned()) {
                missing.push(c);
            }
        }

        if missing.is_empty() {
            Ok(Self {
                auth_pred: Mutex::new(false),
                auth_condvar: Condvar::new(),
                auth_urls: Mutex::new(HashMap::new()),
            })
        } else {
            Err(format!(
                "Notification protocol does not have required capability(s): {}",
                missing.join(", ")
            )
            .into())
        }
    }

    fn main_loop(self: Arc<Self>) -> Result<(), Box<dyn Error>> {
        thread::spawn(move || {
            let mut auth_timeout: Option<Instant> = None;
            // auth_handle and auth_urls are both either `None` or `Some`.
            let mut auth_handle: Option<NotificationHandle> = None;
            let mut auth_urls = HashMap::new();
            loop {
                let mut auth_lk = self.auth_pred.lock().unwrap();
                while !*auth_lk {
                    match auth_timeout {
                        Some(t) => {
                            if Instant::now() > t {
                                break;
                            }
                            match t.checked_duration_since(Instant::now()) {
                                Some(d) => {
                                    auth_lk = self.auth_condvar.wait_timeout(auth_lk, d).unwrap().0
                                }
                                None => break,
                            }
                        }
                        None => auth_lk = self.auth_condvar.wait(auth_lk).unwrap(),
                    }
                }
                *auth_lk = false;
                drop(auth_lk);

                let mut auth_urls_changed = false;
                {
                    let mut auth_urls_lk = self.auth_urls.lock().unwrap();
                    if !auth_urls_lk.is_empty() {
                        for (act_name, url) in auth_urls_lk.drain() {
                            match url {
                                Some(x) => {
                                    auth_urls.insert(act_name, x);
                                }
                                None => {
                                    auth_urls.remove(&act_name);
                                }
                            }
                        }
                        auth_urls_changed = true;
                    }
                }

                if !auth_urls_changed || auth_urls.is_empty() {
                    if let Some(t) = auth_timeout {
                        if Instant::now() < t && !auth_urls.is_empty() {
                            continue;
                        }
                    }

                    if auth_handle.is_some() {
                        auth_handle.unwrap().close();
                        auth_urls.drain();
                        auth_handle = None;
                        auth_timeout = None;
                    }
                    continue;
                }

                auth_timeout =
                    match Instant::now().checked_add(Duration::from_secs(NOTIFICATION_TIMEOUT)) {
                        Some(t) => Some(t),
                        None => Some(Instant::now()),
                    };
                let mut act_names = auth_urls.keys().collect::<Vec<_>>();
                act_names.sort();
                let mut body = Vec::new();
                match get_server_information() {
                    Ok(x) if x.name == "Xfce Notify Daemon" => {
                        // XFCE's Notify Daemon doesn't seem able to parse '&' characters so we
                        // brute-force replace them with '&amp;'.
                        for act_name in act_names {
                            body.push(format!(
                                "<a href=\"{}\">{}</a>",
                                auth_urls[act_name].to_string().replace('&', "&amp;"),
                                act_name
                            ));
                        }
                    }
                    _ => {
                        for act_name in act_names {
                            body.push(format!(
                                "<a href=\"{}\">{}</a>",
                                auth_urls[act_name].to_string(),
                                act_name
                            ));
                        }
                    }
                }
                let body = body.join("\n");
                let mut notification = Notification::new();
                notification
                    .summary("pizauth: Authorization URLs")
                    .body(&body)
                    .appname("pizauth")
                    .timeout(Timeout::Never);

                match auth_handle {
                    Some(ref mut h) => {
                        **h = notification;
                        h.update();
                    }
                    None => match notification.show() {
                        Ok(h) => auth_handle = Some(h),
                        Err(e) => error!("{e:}"),
                    },
                }
            }
        });

        // This frontend has nothing to do in its main loop, so we just want to make sure that we
        // don't terminate the whole program by returning early. Duration::MAX equates to about
        // 584,942,417,355 years which is about 40x the age of the universe at the time of writing.
        // Still, this is meant to be a long-running daemon, so we loop, just in case the timeout
        // is exceeded.
        loop {
            thread::sleep(Duration::MAX);
        }
    }

    fn notify_error(&self, act_name: String, msg: &str) -> Result<(), Box<dyn Error>> {
        let mut lk = self.auth_urls.lock().unwrap();
        lk.insert(act_name.clone(), None);
        drop(lk);
        *self.auth_pred.lock().unwrap() = true;
        self.auth_condvar.notify_one();

        match Notification::new()
            .summary(&format!("pizauth: Authentication failed"))
            .body(&format!("{act_name:}: {msg:}"))
            .appname("pizauth")
            .show()
        {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn notify_success(&self, act_name: String) -> Result<(), Box<dyn Error>> {
        let mut lk = self.auth_urls.lock().unwrap();
        lk.insert(act_name, None);
        drop(lk);
        *self.auth_pred.lock().unwrap() = true;
        self.auth_condvar.notify_one();
        Ok(())
    }

    fn notify_authorisations(&self, to_notify: Vec<(String, Url)>) -> Result<(), Box<dyn Error>> {
        let mut lk = self.auth_urls.lock().unwrap();
        for (act_name, url) in to_notify.into_iter() {
            lk.insert(act_name, Some(url));
        }
        drop(lk);
        *self.auth_pred.lock().unwrap() = true;
        self.auth_condvar.notify_one();
        Ok(())
    }
}
