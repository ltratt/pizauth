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
use log::error;

use super::{expiry_instant, AccountId, AuthenticatorState, CTGuard, TokenState, UREQ_TIMEOUT};

/// The outcome of an attempted refresh.
pub enum RefreshKind {
    /// Refreshing terminated because the config or tokenstate changed.
    AccountOrTokenStateChanged,
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
        mut act_id: AccountId,
    ) -> RefreshKind {
        let refresh_token = match ct_lk.tokenstate(act_id) {
            TokenState::Active {
                refresh_token: Some(refresh_token),
                ..
            } => refresh_token.to_owned(),
            _ => unreachable!("tokenstate is not TokenState::Active"),
        };

        let mut new_ts = ct_lk.tokenstate(act_id).clone();
        if let TokenState::Active {
            ref mut last_refresh_attempt,
            ..
        } = new_ts
        {
            *last_refresh_attempt = Some(Instant::now());
            act_id = ct_lk.tokenstate_replace(act_id, new_ts);
        }

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
                let refreshed_at = Instant::now();
                let mut ct_lk = pstate.ct_lock();
                if ct_lk.is_act_id_valid(act_id) {
                    let expiry = match expiry_instant(&ct_lk, act_id, refreshed_at, expires_in) {
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
                            expiry,
                            refreshed_at,
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
                mut expiry,
                refreshed_at,
                last_refresh_attempt,
                ..
            } => {
                let act = &ct_lk.account(act_id);
                if let Some(lra) = last_refresh_attempt {
                    // There are two ways for `last_refresh_attempt` to be non-`None`:
                    //   1. The token expired (i.e. last_refresh_attempt > expiry).
                    //   2. The user tried manually refreshing the token but that refreshing has
                    //      not yet succeeded (and it is possible that last_refresh_attempt <
                    //      expiry).
                    // If the second case occurs, we assume that the user knows that the token
                    // really needs refreshing, and we treat the token as if it had expired.
                    if let Some(t) = lra.checked_add(act.refresh_retry) {
                        return Some(t.to_owned());
                    }
                }

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
        thread::spawn(move || {
            // There is a potential race where we start a new thread refreshing but before it has
            // updated `TokenState::last_refresh_time` we read the "old" value and assume we need
            // to try refreshing again. `recent_refreshes` stops us starting two threads for the
            // same [AccountId].
            let mut recent_refreshes = HashSet::new();
            loop {
                let next_wakeup = refresher.next_wakeup(&pstate);
                let mut refresh_lk = refresher.pred.lock().unwrap();
                while !*refresh_lk {
                    match next_wakeup {
                        Some(t) => match t.checked_duration_since(Instant::now()) {
                            Some(d) => {
                                #[cfg(debug_assertions)]
                                debug!("Refresher: next wakeup {}", d.as_secs().to_string());
                                refresh_lk =
                                    refresher.condvar.wait_timeout(refresh_lk, d).unwrap().0
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
                    if !recent_refreshes.contains(act_id) {
                        refresher.try_refresh(Arc::clone(&pstate), *act_id);
                    }
                }
                recent_refreshes = to_refresh;
                // It's safe for us to immediately recheck whether there's anything to refresh
                // since `recent_refreshes` stops us trying to endlessly refresh the same
                // [AccountId]. However, the chances are that if we go around the loop immediately
                // then none of the refresh threads will have started, and we'll spin pointlessly.
                // This sleep is intended to largely stop that spinning without unduly pausing the
                // main refresher thread.
                thread::sleep(Duration::from_micros(250));
            }
        });
        Ok(())
    }

    fn try_refresh(self: &Arc<Self>, pstate: Arc<AuthenticatorState>, act_id: AccountId) {
        let refresher = Arc::clone(&self);
        thread::spawn(move || {
            // We abuse a `for` loop here to cope with the case where:
            //   1. The user specifies `expect_transient_error_if`,
            //   2. Refreshing fails due to a transient error e.g. due to a network error.
            //   3. `expect_transient_error_if` succeeds because the source of the transient error
            //      has disappeared.
            // In other words, if `expect_transient_error_if` succeeds, we really want to try
            // refreshing once, because it might now succeed: it's only if
            // `expect_transient_error_if` succeeds twice in a row that we set the tokenstate to
            // `Empty`.
            for i in 0..2 {
                let ct_lk = pstate.ct_lock();
                if ct_lk.is_act_id_valid(act_id) {
                    if let TokenState::Active {
                        last_refresh_attempt,
                        ..
                    } = ct_lk.tokenstate(act_id)
                    {
                        let refreshed_at_least_once = last_refresh_attempt.is_some();
                        match refresher.refresh(&pstate, ct_lk, act_id) {
                            RefreshKind::AccountOrTokenStateChanged | RefreshKind::Refreshed => (),
                            RefreshKind::TransitoryError(act_id, _msg) => {
                                let ct_lk = pstate.ct_lock();
                                // Make sure that we try refreshing at least twice.
                                if refreshed_at_least_once && ct_lk.is_act_id_valid(act_id) {
                                    if let Some(ref cmd) = ct_lk.config().expect_transient_errors_if
                                    {
                                        let cmd = cmd.to_owned();
                                        drop(ct_lk);
                                        match env::var("SHELL") {
                                            Ok(s) => match Command::new(s)
                                                .stdin(Stdio::null())
                                                .stdout(Stdio::null())
                                                .stderr(Stdio::null())
                                                .args(["-c", &cmd])
                                                .spawn()
                                            {
                                                Ok(mut child) => match child.wait() {
                                                    Ok(status) => {
                                                        if status.success() {
                                                            if i == 0 {
                                                                continue;
                                                            }
                                                            let mut ct_lk = pstate.ct_lock();
                                                            if ct_lk.is_act_id_valid(act_id) {
                                                                ct_lk.tokenstate_replace(
                                                                    act_id,
                                                                    TokenState::Empty,
                                                                );
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!("Waiting on '{cmd:}' failed: {e:}")
                                                    }
                                                },
                                                Err(e) => error!("Couldn't execute '{cmd:}': {e:}"),
                                            },
                                            Err(e) => error!("{e:}"),
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
                break;
            }
        });
    }
}
