//! A front-end using the [notify-rust crate](https://crates.io/crates/notify-rust).

use std::{error::Error, thread::sleep, time::Duration};

use notify_rust::{get_capabilities, get_server_information, Notification, Timeout};
use url::Url;

use super::Frontend;

const NOTIFICATION_TIMEOUT: u32 = 1000 * 30; // Milliseconds

pub struct NotifyRust;

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
            Ok(Self)
        } else {
            Err(format!(
                "Notification protocol does not have required capability(s): {}",
                missing.join(", ")
            )
            .into())
        }
    }

    fn main_loop(&self) -> Result<(), Box<dyn Error>> {
        // This frontend has nothing to do in its main loop, so we just want to make sure that we
        // don't terminate the whole program by returning early. Duration::MAX equates to about
        // 584,942,417,355 years which is about 40x the age of the universe at the time of writing.
        // Still, this is meant to be a long-running daemon, so we loop, just in case the timeout
        // is exceeded.
        loop {
            sleep(Duration::MAX);
        }
    }

    fn notify_authorisations(&self, to_notify: Vec<(String, Url)>) -> Result<(), Box<dyn Error>> {
        let body = match get_server_information() {
            Ok(x) if x.name == "Xfce Notify Daemon" => {
                // XFCE's Notify Daemon doesn't seem able to parse '&' characters so we
                // brute-force replace them with '&amp;'.
                to_notify
                    .iter()
                    .map(|(act_name, url)| {
                        format!(
                            "<a href=\"{}\">{}</a>",
                            url.to_string().replace('&', "&amp;"),
                            act_name
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("<br>")
            }
            _ => to_notify
                .iter()
                .map(|(act_name, url)| format!("<a href=\"{}\">{}</a>", url, act_name))
                .collect::<Vec<_>>()
                .join("<br>"),
        };

        // Show the notification.
        match Notification::new()
            .summary("pizauth authorisation URLs")
            .body(&body)
            .appname("pizauth")
            .timeout(Timeout::Milliseconds(NOTIFICATION_TIMEOUT))
            .show()
        {
            Ok(h) => {
                // Block until the notification disappears from screen.
                h.wait_for_action(|_| ());
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
}
