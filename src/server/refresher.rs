use std::{
    cmp,
    collections::{HashMap, HashSet},
    error::Error,
    sync::{Arc, Condvar, Mutex, MutexGuard},
    thread,
    time::{Duration, Instant},
};

use log::{debug, error, info, warn};

use super::{AuthenticatorState, Config, TokenState};

pub struct Refresher {
    pred: Mutex<bool>,
    condvar: Condvar,
}

/// Force a refresh of the token for `act_name`, blocking until the token is refreshed or an error
/// occurred.
pub fn refresh(pstate: Arc<AuthenticatorState>, act_name: String) -> Result<(), Box<dyn Error>> {
    let ct_lk = pstate.conf_tokens.lock().unwrap();
    let act = match ct_lk.0.accounts.get(&act_name) {
        Some(x) => x,
        None => {
            // Account has been deleted on config reload.
            return Ok(());
        }
    };
    let refresh_token = match ct_lk.1.get(&act_name).unwrap() {
        TokenState::Active {
            refresh_token: Some(refresh_token),
            ..
        } => refresh_token.to_owned(),
        _ => {
            warn!("Can't refresh {act_name:}: no refresh token");
            return Ok(());
        }
    };

    let token_uri = act.token_uri.clone();
    let client_id = act.client_id.clone();
    let client_secret = act.client_secret.clone();
    let pairs = [
        ("client_id", client_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("refresh_token", refresh_token.as_str()),
        ("grant_type", "refresh_token"),
    ];
    // Make sure that we don't hold the lock while performing a network request.
    drop(ct_lk);
    let body = ureq::post(token_uri.as_str())
        .send_form(&pairs)?
        .into_string()?;
    let parsed = json::parse(&body)?;

    match (
        parsed["access_token"].as_str(),
        parsed["expires_in"].as_u64(),
        parsed["token_type"].as_str(),
    ) {
        (Some(access_token), Some(expires_in), Some(token_type)) if token_type == "Bearer" => {
            let refreshed_at = Instant::now();
            let expiry = refreshed_at
                .checked_add(Duration::from_secs(expires_in))
                .ok_or("Can't represent expiry")?;
            let mut ct_lk = pstate.conf_tokens.lock().unwrap();
            if let Some(e) = ct_lk.1.get_mut(&act_name) {
                // We don't know what TokenState `e` will be in at this point: it could even be
                // that the user has requested to refresh it entirely in the period we dropped the
                // lock. But a) that's very unlikely b) an active token is generally a good thing.
                info!(
                    "Refreshed {act_name:} (token valid for {} seconds)",
                    expires_in
                );
                *e = TokenState::Active {
                    access_token: access_token.to_owned(),
                    expiry,
                    refreshed_at,
                    refresh_token: Some(refresh_token),
                };
            }
            drop(ct_lk);
        }
        _ => return Err("Received JSON in unexpected format".into()),
    }

    Ok(())
}

/// If `act_name` has an active token, return the time when that token should be refreshed.
///
/// # Panics
///
/// If `act_name` does not exist.
fn refresh_at(
    _pstate: &AuthenticatorState,
    ct_lk: &MutexGuard<(Config, HashMap<String, TokenState>)>,
    act_name: &str,
) -> Option<Instant> {
    debug_assert!(ct_lk.1.contains_key(act_name));
    match ct_lk.1[act_name] {
        TokenState::Active {
            mut expiry,
            refreshed_at,
            ..
        } => {
            let act = &ct_lk.0.accounts[act_name];
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

fn next_wakeup(pstate: &AuthenticatorState) -> Option<Instant> {
    let ct_lk = pstate.conf_tokens.lock().unwrap();
    ct_lk
        .1
        .keys()
        .filter_map(|act_name| refresh_at(pstate, &ct_lk, act_name))
        .min()
}

pub fn update_refresher(pstate: Arc<AuthenticatorState>) {
    let mut refresh_lk = pstate.refresher.pred.lock().unwrap();
    *refresh_lk = true;
    pstate.refresher.condvar.notify_one();
}

pub fn refresher_setup() -> Result<Refresher, Box<dyn Error>> {
    Ok(Refresher {
        pred: Mutex::new(false),
        condvar: Condvar::new(),
    })
}

pub fn refresher(pstate: Arc<AuthenticatorState>) -> Result<(), Box<dyn Error>> {
    thread::spawn(move || loop {
        let next_wakeup = next_wakeup(&pstate);
        let mut refresh_lk = pstate.refresher.pred.lock().unwrap();
        while !*refresh_lk {
            #[cfg(debug_assertions)]
            debug!(
                "Refresher: next wakeup {}",
                next_wakeup
                    .map(|x| x
                        .checked_duration_since(Instant::now())
                        .map(|x| x.as_secs().to_string())
                        .unwrap_or("<none>".to_owned()))
                    .unwrap_or("none".to_owned())
            );
            match next_wakeup {
                Some(t) => {
                    if Instant::now() >= t {
                        break;
                    }
                    match t.checked_duration_since(Instant::now()) {
                        Some(d) => {
                            refresh_lk = pstate
                                .refresher
                                .condvar
                                .wait_timeout(refresh_lk, d)
                                .unwrap()
                                .0
                        }
                        None => break,
                    }
                }
                None => refresh_lk = pstate.refresher.condvar.wait(refresh_lk).unwrap(),
            }
        }

        *refresh_lk = false;
        drop(refresh_lk);

        let mut to_refresh = HashSet::<String>::new();
        let ct_lk = pstate.conf_tokens.lock().unwrap();
        let now = Instant::now();
        for act_name in ct_lk.1.keys() {
            if refresh_at(&pstate, &ct_lk, act_name) <= Some(now) {
                to_refresh.insert(act_name.to_owned());
            }
        }
        drop(ct_lk);

        for act_name in to_refresh {
            if let Err(e) = refresh(Arc::clone(&pstate), act_name.clone()) {
                error!("Token refresh failed: {e:}");
            }
        }
    });

    Ok(())
}
