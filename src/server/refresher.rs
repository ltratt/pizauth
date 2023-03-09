use std::{
    cmp,
    collections::HashSet,
    env,
    error::Error,
    process::{Command, Stdio},
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};

#[cfg(debug_assertions)]
use log::debug;
use wait_timeout::ChildExt;

use super::{expiry_instant, AccountId, AuthenticatorState, CTGuard, TokenState, UREQ_TIMEOUT};

/// How many times can a transient error be encountered before we try `not_transient_error_if`?
const TRANSIENT_ERROR_RETRIES: u64 = 6;
/// How long to run `not_transient_error_if` commands before killing them?
const NOT_TRANSIENT_ERROR_IF_TIMEOUT: Duration = Duration::from_secs(3 * 60);

/// The outcome of an attempted refresh.
enum RefreshKind {
    /// Refreshing terminated because the config or tokenstate changed.
    AccountOrTokenStateChanged,
    /// There is no refresh token so refreshing cannot succeed.
    NoRefreshToken,
    /// Refreshing failed in a way that is likely to repeat if retried.
    PermanentError(String),
    /// The token was refreshed.
    Refreshed,
    /// Refreshing failed but in a way that is not likely to repeat if retried.
    TransitoryError(AccountId, String),
}

pub struct Refresher {
    pred: Mutex<bool>,
    condvar: Condvar,
}

impl Refresher {
    pub fn new() -> Arc<Self> {
        Arc::new(Refresher {
            pred: Mutex::new(false),
            condvar: Condvar::new(),
        })
    }

    pub fn sched_refresh(self: &Arc<Self>, pstate: Arc<AuthenticatorState>, act_id: AccountId) {
        let refresher = Arc::clone(self);
        thread::spawn(move || {
            let mut ct_lk = pstate.ct_lock();
            if ct_lk.is_act_id_valid(act_id) {
                let mut new_ts = ct_lk.tokenstate(act_id).clone();
                if let TokenState::Active {
                    ref mut ongoing_refresh,
                    ..
                } = new_ts
                {
                    if !*ongoing_refresh {
                        *ongoing_refresh = true;
                        let act_id = ct_lk.tokenstate_replace(act_id, new_ts);
                        let act_name = ct_lk.account(act_id).name.clone();
                        match refresher.inner_refresh(&pstate, ct_lk, act_id) {
                            RefreshKind::AccountOrTokenStateChanged => (),
                            RefreshKind::NoRefreshToken => (),
                            RefreshKind::PermanentError(msg) => {
                                pstate
                                    .notifier
                                    .notify_error(
                                        &pstate,
                                        act_name,
                                        format!("Permanent refresh error: {msg:}"),
                                    )
                                    .ok();
                            }
                            RefreshKind::Refreshed => (),
                            RefreshKind::TransitoryError(act_id, msg) => {
                                ct_lk = pstate.ct_lock();
                                if ct_lk.is_act_id_valid(act_id) {
                                    let mut new_ts = ct_lk.tokenstate(act_id).clone();
                                    if let TokenState::Active {
                                        ref mut last_refresh_attempt,
                                        ref mut consecutive_refresh_fails,
                                        ..
                                    } = new_ts
                                    {
                                        *last_refresh_attempt = Some(Instant::now());
                                        *consecutive_refresh_fails += 1;
                                        let consecutive_refresh_fails = *consecutive_refresh_fails;
                                        let act_id = ct_lk.tokenstate_replace(act_id, new_ts);
                                        if consecutive_refresh_fails
                                            .rem_euclid(TRANSIENT_ERROR_RETRIES)
                                            == 0
                                        {
                                            if let Some(ref cmd) = ct_lk
                                                .account(act_id)
                                                .not_transient_error_if(ct_lk.config())
                                            {
                                                let cmd = cmd.to_owned();
                                                drop(ct_lk);
                                                match refresher.run_not_transient_error_if(cmd) {
                                                    Ok(()) => {
                                                        ct_lk = pstate.ct_lock();
                                                        if ct_lk.is_act_id_valid(act_id) {
                                                            ct_lk.tokenstate_set_ongoing_refresh(
                                                                act_id, false,
                                                            );
                                                        }
                                                        drop(ct_lk);
                                                    }
                                                    Err(e) => {
                                                        ct_lk = pstate.ct_lock();
                                                        if ct_lk.is_act_id_valid(act_id) {
                                                            ct_lk.tokenstate_replace(
                                                                act_id,
                                                                TokenState::Empty,
                                                            );
                                                        }
                                                        drop(ct_lk);
                                                        pstate
                                                            .notifier
                                                            .notify_error(
                                                                &pstate,
                                                                act_name,
                                                                format!(
                                                                    "Permanent refresh error: {e:}"
                                                                ),
                                                            )
                                                            .ok();
                                                    }
                                                };
                                            } else {
                                                ct_lk.tokenstate_set_ongoing_refresh(act_id, false);
                                                drop(ct_lk);
                                                pstate
                                                    .notifier
                                                    .notify_error(
                                                        &pstate,
                                                        act_name,
                                                        format!(
                                                            "Transitory token refresh error: {msg:}"
                                                        ),
                                                    )
                                                    .ok();
                                            }
                                        } else {
                                            ct_lk.tokenstate_set_ongoing_refresh(act_id, false);
                                            drop(ct_lk);
                                        }
                                    } else {
                                        unreachable!();
                                    }
                                } else {
                                    drop(ct_lk);
                                }
                                // If the main refresher thread noticed we were running it
                                // might have given up, so give it a chance to recalculate when
                                // it should next wake up.
                                refresher.notify_changes();
                            }
                        }
                    }
                }
            }
        });
    }

    fn run_not_transient_error_if(&self, cmd: String) -> Result<(), String> {
        match env::var("SHELL") {
            Ok(s) => match Command::new(s)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .args(["-c", &cmd])
                .spawn()
            {
                Ok(mut child) => match child.wait_timeout(NOT_TRANSIENT_ERROR_IF_TIMEOUT) {
                    Ok(Some(status)) => {
                        if !status.success() {
                            Ok(())
                        } else {
                            Err(format!(
                                "'{cmd:}' returned {}",
                                status
                                    .code()
                                    .map(|x| x.to_string())
                                    .unwrap_or_else(|| "<Unknown exit code".to_string())
                            ))
                        }
                    }
                    Ok(None) => {
                        child.kill().ok();
                        child.wait().ok();
                        Err(format!("'{cmd:}' exceeded timeout"))
                    }
                    Err(e) => Err(format!("Waiting on '{cmd:}' failed: {e:}")),
                },
                Err(e) => Err(format!("Couldn't execute '{cmd:}': {e:}")),
            },
            Err(e) => Err(format!("{e:}")),
        }
    }

    /// For a [TokenState::Active] token for `act_id`, refresh it, blocking until the token is
    /// refreshed or an error occurred. This function must be called with a [TokenState::Active]
    /// tokenstate.
    ///
    /// # Panics
    ///
    /// If the tokenstate is not [TokenState::Active].
    fn inner_refresh(
        &self,
        pstate: &AuthenticatorState,
        mut ct_lk: CTGuard,
        mut act_id: AccountId,
    ) -> RefreshKind {
        let mut new_ts = ct_lk.tokenstate(act_id).clone();
        let refresh_token = match new_ts {
            TokenState::Active {
                ref refresh_token,
                ref mut last_refresh_attempt,
                ..
            } => match refresh_token {
                Some(r) => {
                    *last_refresh_attempt = Some(Instant::now());
                    let r = r.to_owned();
                    act_id = ct_lk.tokenstate_replace(act_id, new_ts);
                    r
                }
                None => {
                    ct_lk.tokenstate_replace(act_id, TokenState::Empty);
                    return RefreshKind::NoRefreshToken;
                }
            },
            _ => unreachable!("tokenstate is not TokenState::Active"),
        };

        let act = ct_lk.account(act_id);
        let token_uri = act.token_uri.clone();
        let client_id = act.client_id.clone();
        let mut pairs = vec![
            ("client_id", client_id.as_str()),
            ("refresh_token", refresh_token.as_str()),
            ("grant_type", "refresh_token"),
        ];
        let client_secret = act.client_secret.clone();
        if let Some(ref x) = client_secret {
            pairs.push(("client_secret", x));
        }

        drop(ct_lk);
        let body = match ureq::AgentBuilder::new()
            .timeout(UREQ_TIMEOUT)
            .build()
            .post(token_uri.as_str())
            .send_form(&pairs)
        {
            Ok(response) => match response.into_string() {
                Ok(s) => s,
                Err(e) => {
                    return RefreshKind::TransitoryError(act_id, e.to_string());
                }
            },
            Err(ureq::Error::Status(code, response)) => {
                let reason = match response.into_string() {
                    Ok(r) => format!("{code:}: {r:}"),
                    Err(_) => format!("{code:}"),
                };
                let mut ct_lk = pstate.ct_lock();
                if ct_lk.is_act_id_valid(act_id) {
                    ct_lk.tokenstate_replace(act_id, TokenState::Empty);
                    return RefreshKind::PermanentError(reason);
                } else {
                    return RefreshKind::AccountOrTokenStateChanged;
                }
            }
            Err(ref e @ ureq::Error::Transport(ref t))
                if t.kind() == ureq::ErrorKind::ConnectionFailed
                    || t.kind() == ureq::ErrorKind::Dns
                    || t.kind() == ureq::ErrorKind::Io =>
            {
                return RefreshKind::TransitoryError(act_id, e.to_string())
            }
            Err(e) => {
                let mut ct_lk = pstate.ct_lock();
                if ct_lk.is_act_id_valid(act_id) {
                    ct_lk.tokenstate_replace(act_id, TokenState::Empty);
                    return RefreshKind::PermanentError(e.to_string());
                } else {
                    return RefreshKind::AccountOrTokenStateChanged;
                }
            }
        };

        let parsed = match json::parse(&body).map(|p| (p["error"].as_str().is_some(), p)) {
            Err(_) | Ok((true, _)) => {
                // Either JSON parsing failed, or the JSON contains an error field. Unfortunately,
                // even in the latter case, there is no standard way of knowing why refreshing
                // failed, so we take the most pessimistic assumption which is that the refresh
                // token is no longer valid at all.
                let mut ct_lk = pstate.ct_lock();
                if ct_lk.is_act_id_valid(act_id) {
                    let act_id = ct_lk.tokenstate_replace(act_id, TokenState::Empty);
                    let msg = format!("Refreshing {} failed", ct_lk.account(act_id).name);
                    return RefreshKind::PermanentError(msg);
                } else {
                    return RefreshKind::AccountOrTokenStateChanged;
                }
            }
            Ok((false, p)) => p,
        };

        match (
            parsed["access_token"].as_str(),
            parsed["expires_in"].as_u64(),
            parsed["token_type"].as_str(),
        ) {
            (Some(access_token), Some(expires_in), Some(token_type)) if token_type == "Bearer" => {
                let now = Instant::now();
                let mut ct_lk = pstate.ct_lock();
                if ct_lk.is_act_id_valid(act_id) {
                    let expiry = match expiry_instant(&ct_lk, act_id, now, expires_in) {
                        Ok(x) => x,
                        Err(e) => {
                            ct_lk.tokenstate_replace(act_id, TokenState::Empty);
                            return RefreshKind::PermanentError(format!("{e}"));
                        }
                    };
                    ct_lk.tokenstate_replace(
                        act_id,
                        TokenState::Active {
                            access_token: access_token.to_owned(),
                            access_token_obtained: now,
                            access_token_expiry: expiry,
                            ongoing_refresh: false,
                            consecutive_refresh_fails: 0,
                            last_refresh_attempt: None,
                            refresh_token: Some(refresh_token),
                        },
                    );
                    drop(ct_lk);
                    self.notify_changes();
                    RefreshKind::Refreshed
                } else {
                    RefreshKind::AccountOrTokenStateChanged
                }
            }
            _ => {
                let mut ct_lk = pstate.ct_lock();
                if ct_lk.is_act_id_valid(act_id) {
                    ct_lk.tokenstate_replace(act_id, TokenState::Empty);
                    RefreshKind::PermanentError("Received JSON in unexpected format".to_string())
                } else {
                    RefreshKind::AccountOrTokenStateChanged
                }
            }
        }
    }

    /// If `act_id` has an active token, return the time when that token should be refreshed.
    fn refresh_at(
        &self,
        _pstate: &AuthenticatorState,
        ct_lk: &CTGuard,
        act_id: AccountId,
    ) -> Option<Instant> {
        match ct_lk.tokenstate(act_id) {
            TokenState::Active {
                access_token_obtained,
                access_token_expiry,
                ongoing_refresh,
                last_refresh_attempt,
                ..
            } if !ongoing_refresh => {
                let act = &ct_lk.account(act_id);
                if let Some(lra) = last_refresh_attempt {
                    // There are two ways for `last_refresh_attempt` to be non-`None`:
                    //   1. The token expired (i.e. last_refresh_attempt > expiry).
                    //   2. The user tried manually refreshing the token but that refreshing has
                    //      not yet succeeded (and it is possible that last_refresh_attempt <
                    //      expiry).
                    // If the second case occurs, we assume that the user knows that the token
                    // really needs refreshing, and we treat the token as if it had expired.
                    if let Some(t) = lra.checked_add(act.refresh_retry(ct_lk.config())) {
                        return Some(t.to_owned());
                    }
                }

                let mut expiry = access_token_expiry
                    .checked_sub(act.refresh_before_expiry(ct_lk.config()))
                    .unwrap_or_else(|| cmp::min(Instant::now(), *access_token_expiry));

                // There is no concept of Instant::MAX, so if `access_token_obtained + d` exceeds
                // Instant's bounds, there's nothing we can fall back on.
                if let Some(t) =
                    access_token_obtained.checked_add(act.refresh_at_least(ct_lk.config()))
                {
                    expiry = cmp::min(expiry, t);
                }
                Some(expiry.to_owned())
            }
            _ => None,
        }
    }

    fn next_wakeup(&self, pstate: &AuthenticatorState) -> Option<Instant> {
        let ct_lk = pstate.ct_lock();
        ct_lk
            .act_ids()
            .filter_map(|act_id| self.refresh_at(pstate, &ct_lk, act_id))
            .min()
    }

    /// Notify the refresher that one or more [TokenState]s is likely to have changed in a way that
    /// effects the refresher.
    pub fn notify_changes(&self) {
        let mut refresh_lk = self.pred.lock().unwrap();
        *refresh_lk = true;
        self.condvar.notify_one();
    }

    /// Start the refresher thread.
    pub fn refresher(
        self: Arc<Self>,
        pstate: Arc<AuthenticatorState>,
    ) -> Result<(), Box<dyn Error>> {
        let refresher = Arc::clone(&self);
        thread::spawn(move || loop {
            let next_wakeup = refresher.next_wakeup(&pstate);
            let mut refresh_lk = refresher.pred.lock().unwrap();
            while !*refresh_lk {
                match next_wakeup {
                    Some(t) => match t.checked_duration_since(Instant::now()) {
                        Some(d) => {
                            #[cfg(debug_assertions)]
                            debug!("Refresher: next wakeup {}", d.as_secs().to_string());
                            refresh_lk = refresher.condvar.wait_timeout(refresh_lk, d).unwrap().0
                        }
                        None => break,
                    },
                    None => {
                        #[cfg(debug_assertions)]
                        debug!("Refresher: next wakeup <indefinite>");
                        refresh_lk = refresher.condvar.wait(refresh_lk).unwrap();
                    }
                }
            }

            *refresh_lk = false;
            drop(refresh_lk);

            let ct_lk = pstate.ct_lock();
            let now = Instant::now();
            let to_refresh = ct_lk
                .act_ids()
                .filter(
                    |act_id| match refresher.refresh_at(&pstate, &ct_lk, *act_id) {
                        Some(t) => t <= now,
                        None => false,
                    },
                )
                .collect::<HashSet<_>>();
            drop(ct_lk);

            for act_id in to_refresh.iter() {
                refresher.sched_refresh(Arc::clone(&pstate), *act_id);
            }
        });
        Ok(())
    }
}
