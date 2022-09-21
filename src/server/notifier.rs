use std::{
    env,
    error::Error,
    process::Command,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::Instant,
};

#[cfg(debug_assertions)]
use log::debug;
use log::error;

use super::{AuthenticatorState, CTGuard, CTGuardAccountId, TokenState};

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
            let next_wakeup = self.next_wakeup(&pstate);
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

            let mut auth_cmds = Vec::new();
            let mut ct_lk = pstate.ct_lock();
            let now = Instant::now();
            let notify_interval = ct_lk.config().notify_interval; // Pulled out to avoid borrow checker problems.
            for act_id in ct_lk.act_ids().collect::<Vec<_>>() {
                let mut ts = ct_lk.tokenstate(&act_id).clone();
                if let TokenState::Pending {
                    ref mut last_notification,
                    ref url,
                    ..
                } = ts
                {
                    if let Some(t) = last_notification {
                        if let Some(t) = t.checked_add(notify_interval) {
                            if t > now {
                                continue;
                            }
                        }
                    }
                    *last_notification = Some(now);
                    let url = url.clone();
                    let act = ct_lk.account(&act_id);
                    auth_cmds.push((act.name.to_owned(), act.auth_cmd.clone(), url));
                    ct_lk.tokenstate_replace(act_id, ts);
                }
            }
            drop(ct_lk);

            for (act_name, cmd, url) in auth_cmds.into_iter() {
                thread::spawn(move || match env::var("SHELL") {
                    Ok(s) => {
                        match Command::new(s)
                            .env("PIZAUTH_URL", url.as_str())
                            .args(["-c", &cmd])
                            .output()
                        {
                            Ok(output) => {
                                if !output.status.success() {
                                    error!(
                                        "{act_name:}: error when running '{cmd:}': {}",
                                        std::str::from_utf8(&output.stdout).unwrap_or_else(|_| {
                                            "<stderr not representable as UTF-8"
                                        })
                                    );
                                }
                            }
                            Err(e) => error!("{act_name:}: error when running '{cmd:}': {e:}"),
                        }
                    }
                    Err(e) => error!("{e:}"),
                });
            }
        });

        Ok(())
    }

    pub fn notify_new(&self, _pstate: Arc<AuthenticatorState>) {
        let mut notify_lk = self.pred.lock().unwrap();
        *notify_lk = true;
        self.condvar.notify_one();
    }

    fn next_wakeup(&self, pstate: &AuthenticatorState) -> Option<Instant> {
        let ct_lk = pstate.ct_lock();
        ct_lk
            .act_ids()
            .filter_map(|act_id| notify_at(pstate, &ct_lk, &act_id))
            .min()
    }

    pub fn notify_error(
        &self,
        _act_name: String,
        _msg: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // FIXME
        Ok(())
    }

    pub fn notify_success(&self, _act_name: String) -> Result<(), Box<dyn std::error::Error>> {
        // FIXME
        Ok(())
    }
}

/// If `act_id` has a pending token, return the next time when that user should be notified that
/// it is pending.
fn notify_at(
    _pstate: &AuthenticatorState,
    ct_lk: &CTGuard,
    act_id: &CTGuardAccountId,
) -> Option<Instant> {
    match ct_lk.tokenstate(act_id) {
        TokenState::Pending {
            last_notification, ..
        } => {
            match last_notification {
                None => Some(Instant::now()),
                Some(t) => {
                    // There is no concept of Instant::MAX, so if `refreshed_at + d` exceeds
                    // Instant's bounds, there's nothing we can fall back on.
                    t.checked_add(ct_lk.config().notify_interval)
                }
            }
        }
        _ => None,
    }
}
