use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, Condvar, Mutex, MutexGuard},
    thread,
    time::Instant,
};

#[cfg(debug_assertions)]
use log::debug;
use log::error;

use super::{AuthenticatorState, Config, TokenState};

pub struct Notifier {
    pred: Mutex<bool>,
    condvar: Condvar,
}

impl Notifier {
    pub fn new() -> Result<Notifier, Box<dyn Error>> {
        Ok(Notifier {
            pred: Mutex::new(false),
            condvar: Condvar::new(),
        })
    }

    pub fn notifier(
        self: Arc<Self>,
        pstate: Arc<AuthenticatorState>,
    ) -> Result<(), Box<dyn Error>> {
        thread::spawn(move || loop {
            let next_wakeup = Arc::clone(&self).next_wakeup(&pstate);
            let mut notify_lk = self.pred.lock().unwrap();
            while !*notify_lk {
                #[cfg(debug_assertions)]
                debug!(
                    "Notifier: next wakeup {}",
                    next_wakeup
                        .map(|x| x
                            .checked_duration_since(Instant::now())
                            .map(|x| x.as_secs().to_string())
                            .unwrap_or_else(|| "<none>".to_owned()))
                        .unwrap_or_else(|| "<none>".to_owned())
                );
                match next_wakeup {
                    Some(t) => {
                        if Instant::now() >= t {
                            break;
                        }
                        match t.checked_duration_since(Instant::now()) {
                            Some(d) => {
                                notify_lk = self.condvar.wait_timeout(notify_lk, d).unwrap().0
                            }
                            None => break,
                        }
                    }
                    None => notify_lk = self.condvar.wait(notify_lk).unwrap(),
                }
            }
            *notify_lk = false;
            drop(notify_lk);

            let mut to_notify = Vec::new();
            let mut ct_lk = pstate.ct_lock();
            let now = Instant::now();
            let renotify = ct_lk.0.renotify; // Pulled out to avoid borrow checker problems.
            for (name, state) in ct_lk.1.iter_mut() {
                if let TokenState::Pending {
                    ref mut last_notification,
                    state: _,
                    url,
                } = state
                {
                    if let Some(t) = last_notification {
                        if let Some(t) = t.checked_add(renotify) {
                            if t > now {
                                continue;
                            }
                        }
                    }
                    *last_notification = Some(now);
                    to_notify.push((name.clone(), url.clone()));
                }
            }
            drop(ct_lk);

            if to_notify.is_empty() {
                continue;
            }

            if let Err(e) = pstate.frontend.notify(to_notify) {
                error!("Notifier: {e:}");
            }
        });

        Ok(())
    }

    pub fn notify_new(&self, _pstate: Arc<AuthenticatorState>) {
        let mut notify_lk = self.pred.lock().unwrap();
        *notify_lk = true;
        self.condvar.notify_one();
    }

    fn next_wakeup(self: Arc<Self>, pstate: &AuthenticatorState) -> Option<Instant> {
        let ct_lk = pstate.ct_lock();
        ct_lk
            .1
            .keys()
            .filter_map(|act_name| notify_at(pstate, &ct_lk, act_name))
            .min()
    }
}

/// If `act_name` has a pending token, return the next time when that user should be notified that
/// it is pending.
///
/// # Panics
///
/// If `act_name` does not exist.
fn notify_at(
    _pstate: &AuthenticatorState,
    ct_lk: &MutexGuard<(Config, HashMap<String, TokenState>)>,
    act_name: &str,
) -> Option<Instant> {
    debug_assert!(ct_lk.1.contains_key(act_name));
    match ct_lk.1[act_name] {
        TokenState::Pending {
            last_notification, ..
        } => {
            match last_notification {
                None => Some(Instant::now()),
                Some(t) => {
                    // There is no concept of Instant::MAX, so if `refreshed_at + d` exceeds
                    // Instant's bounds, there's nothing we can fall back on.
                    t.checked_add(ct_lk.0.renotify)
                }
            }
        }
        _ => None,
    }
}
