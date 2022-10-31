use std::{
    cmp,
    error::Error,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::Instant,
};

#[cfg(debug_assertions)]
use log::debug;
use log::error;

use super::{
    expiry_instant, AuthenticatorState, CTGuard, CTGuardAccountId, TokenState, UREQ_TIMEOUT,
};

/// The outcome of an attempted refresh.
pub enum RefreshKind {
    /// Refreshing terminated because the config or tokenstate changed.
    AccountOrTokenStateChanged,
    /// Refreshing failed in a way that is likely to repeat if retried.
    PermanentError(String),
    /// The token was refreshed.
    Refreshed,
    /// Refreshing failed but in a way that is not likely to repeat if retried.
    TransitoryError(CTGuardAccountId, String),
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

    /// For a [TokenState::Active] token for `act_id`, refresh it, blocking until the token is
    /// refreshed or an error occurred. This function must be called with a [TokenState::Active]
    /// tokenstate.
    ///
    /// # Panics
    ///
    /// If the tokenstate is not [TokenState::Active].
    pub fn refresh(
        &self,
        pstate: &AuthenticatorState,
        mut ct_lk: CTGuard,
        mut act_id: CTGuardAccountId,
    ) -> RefreshKind {
        let refresh_token = match ct_lk.tokenstate(&act_id) {
            TokenState::Active {
                refresh_token: Some(refresh_token),
                ..
            } => refresh_token.to_owned(),
            _ => unreachable!("tokenstate is not TokenState::Active"),
        };

        let mut new_ts = ct_lk.tokenstate(&act_id).clone();
        if let TokenState::Active {
            ref mut last_refresh_attempt,
            ..
        } = new_ts
        {
            *last_refresh_attempt = Some(Instant::now());
            act_id = ct_lk.tokenstate_replace(act_id, new_ts);
        }

        let act = ct_lk.account(&act_id);
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
                match ct_lk.validate_act_id(act_id) {
                    Some(act_id) => {
                        ct_lk.tokenstate_replace(act_id, TokenState::Empty);
                        return RefreshKind::PermanentError(reason);
                    }
                    None => return RefreshKind::AccountOrTokenStateChanged,
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
                match ct_lk.validate_act_id(act_id) {
                    Some(act_id) => {
                        ct_lk.tokenstate_replace(act_id, TokenState::Empty);
                        return RefreshKind::PermanentError(e.to_string());
                    }
                    None => return RefreshKind::AccountOrTokenStateChanged,
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
                match ct_lk.validate_act_id(act_id) {
                    Some(act_id) => {
                        let act_id = ct_lk.tokenstate_replace(act_id, TokenState::Empty);
                        let msg = format!("Refreshing {} failed", ct_lk.account(&act_id).name);
                        drop(ct_lk);
                        return RefreshKind::PermanentError(msg);
                    }
                    None => return RefreshKind::AccountOrTokenStateChanged,
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
                let refreshed_at = Instant::now();
                let mut ct_lk = pstate.ct_lock();
                match ct_lk.validate_act_id(act_id) {
                    Some(act_id) => {
                        let expiry = match expiry_instant(&ct_lk, &act_id, refreshed_at, expires_in)
                        {
                            Ok(x) => x,
                            Err(e) => {
                                ct_lk.tokenstate_replace(act_id, TokenState::Empty);
                                drop(ct_lk);
                                return RefreshKind::PermanentError(format!("{e}"));
                            }
                        };
                        ct_lk.tokenstate_replace(
                            act_id,
                            TokenState::Active {
                                access_token: access_token.to_owned(),
                                expiry,
                                refreshed_at,
                                last_refresh_attempt: None,
                                last_refresh_warning: None,
                                refresh_token: Some(refresh_token),
                            },
                        );
                        drop(ct_lk);
                        self.notify_changes();
                        RefreshKind::Refreshed
                    }
                    None => RefreshKind::AccountOrTokenStateChanged,
                }
            }
            _ => {
                let mut ct_lk = pstate.ct_lock();
                match ct_lk.validate_act_id(act_id) {
                    Some(act_id) => {
                        ct_lk.tokenstate_replace(act_id, TokenState::Empty);
                        RefreshKind::PermanentError(
                            "Received JSON in unexpected format".to_string(),
                        )
                    }
                    None => RefreshKind::AccountOrTokenStateChanged,
                }
            }
        }
    }

    /// If `act_id` has an active token, return the time when that token should be refreshed.
    fn refresh_at(
        &self,
        _pstate: &AuthenticatorState,
        ct_lk: &CTGuard,
        act_id: &CTGuardAccountId,
    ) -> Option<Instant> {
        match ct_lk.tokenstate(act_id) {
            TokenState::Active {
                mut expiry,
                refreshed_at,
                last_refresh_attempt,
                ..
            } => {
                let act = &ct_lk.account(act_id);
                if let Some(d) = act.refresh_before_expiry {
                    expiry = expiry
                        .checked_sub(d)
                        .unwrap_or_else(|| cmp::min(Instant::now(), expiry));
                }
                if let Some(d) = act.refresh_at_least {
                    // There is no concept of Instant::MAX, so if `refreshed_at + d` exceeds
                    // Instant's bounds, there's nothing we can fall back on.
                    if let Some(t) = refreshed_at.checked_add(d) {
                        expiry = cmp::min(expiry, t);
                    }
                }
                if let Some(lra) = last_refresh_attempt {
                    if let Some(t) = lra.checked_add(act.refresh_retry_interval) {
                        if t > expiry {
                            return Some(t.to_owned());
                        }
                    }
                }
                Some(expiry.to_owned())
            }
            _ => None,
        }
    }

    /// If `act_id` has an active token, return the time when a warning about refreshing failure
    /// should be made.
    fn warn_at(
        &self,
        _pstate: &AuthenticatorState,
        ct_lk: &CTGuard,
        act_id: &CTGuardAccountId,
    ) -> Option<Instant> {
        match ct_lk.tokenstate(act_id) {
            TokenState::Active {
                expiry,
                last_refresh_warning,
                ..
            } => {
                if let Some(x) = last_refresh_warning {
                    x.checked_add(ct_lk.config().refresh_warn_interval)
                } else {
                    expiry.checked_add(ct_lk.config().refresh_warn_interval)
                }
            }
            _ => None,
        }
    }

    fn next_wakeup(&self, pstate: &AuthenticatorState) -> Option<Instant> {
        let ct_lk = pstate.ct_lock();
        ct_lk
            .act_ids()
            .filter_map(|act_id| {
                match (
                    self.refresh_at(pstate, &ct_lk, &act_id),
                    self.warn_at(pstate, &ct_lk, &act_id),
                ) {
                    (Some(x), Some(y)) => Some(cmp::min(x, y)),
                    (Some(x), None) => Some(x),
                    (None, Some(y)) => Some(y),
                    (None, None) => None,
                }
            })
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
        thread::spawn(move || loop {
            let next_wakeup = self.next_wakeup(&pstate);
            let mut refresh_lk = self.pred.lock().unwrap();
            while !*refresh_lk {
                #[cfg(debug_assertions)]
                debug!(
                    "Refresher: next wakeup {}",
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
                                refresh_lk = self.condvar.wait_timeout(refresh_lk, d).unwrap().0
                            }
                            None => break,
                        }
                    }
                    None => refresh_lk = self.condvar.wait(refresh_lk).unwrap(),
                }
            }

            *refresh_lk = false;
            drop(refresh_lk);

            let ct_lk = pstate.ct_lock();
            let now = Instant::now();
            let to_refresh = ct_lk
                .act_ids()
                .filter(|act_id| self.refresh_at(&pstate, &ct_lk, act_id) <= Some(now))
                .collect::<Vec<_>>();
            drop(ct_lk);

            for act_id in to_refresh.into_iter() {
                let ct_lk = pstate.ct_lock();
                if let Some(act_id) = ct_lk.validate_act_id(act_id) {
                    if let TokenState::Active {
                        last_refresh_attempt,
                        ..
                    } = ct_lk.tokenstate(&act_id)
                    {
                        let refreshed_at_least_once = last_refresh_attempt.is_some();
                        match self.refresh(&pstate, ct_lk, act_id) {
                            RefreshKind::AccountOrTokenStateChanged | RefreshKind::Refreshed => (),
                            RefreshKind::TransitoryError(act_id, msg) => {
                                // Has refreshing this token not succeeded for too long a
                                // period?
                                let mut ct_lk = pstate.ct_lock();
                                if let Some(act_id) = ct_lk.validate_act_id(act_id) {
                                    // Make sure that we try refreshing at least twice.
                                    if !refreshed_at_least_once {
                                        continue;
                                    }

                                    // Note that we deliberately use `now` and not a (fresh)
                                    // `Instant::now()` as it is a partial proxy for "the machine
                                    // was suspended during the refreshing process so try once
                                    // more".
                                    if self.warn_at(&pstate, &ct_lk, &act_id) <= Some(now) {
                                        let mut new_ts = ct_lk.tokenstate(&act_id).clone();
                                        if let TokenState::Active {
                                            ref mut last_refresh_warning,
                                            ..
                                        } = new_ts
                                        {
                                            *last_refresh_warning = Some(Instant::now());
                                            let act_id = ct_lk.tokenstate_replace(act_id, new_ts);
                                            match &ct_lk.config().refresh_warn_cmd {
                                                Some(cmd) => {
                                                    if let Err(e) = pstate.notifier.notify_warn(
                                                        &pstate,
                                                        Some(cmd.to_string()),
                                                        ct_lk.account(&act_id).name.clone(),
                                                        msg,
                                                    ) {
                                                        error!("When running auth_warn_cmd: {e:}");
                                                    }
                                                }
                                                None => {
                                                    ct_lk.tokenstate_replace(
                                                        act_id,
                                                        TokenState::Empty,
                                                    );
                                                    error!("Token refresh failed for too long a period")
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            RefreshKind::PermanentError(msg) => {
                                error!("Token refresh failed: {msg:}")
                            }
                        }
                    }
                }
            }
        });

        Ok(())
    }
}
