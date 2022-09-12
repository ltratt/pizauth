use std::{error::Error, sync::Arc};

use rand::{thread_rng, RngCore};
use url::Url;

use super::{AuthenticatorState, CTGuard, CTGuardAccountId, TokenState, STATE_LEN};

/// Request a new token for `act_id`, whose tokenstate must be `Empty`.
pub fn request_token(
    pstate: Arc<AuthenticatorState>,
    mut ct_lk: CTGuard,
    act_id: CTGuardAccountId,
) -> Result<(), Box<dyn Error>> {
    assert!(matches!(
        ct_lk.tokenstate(&act_id),
        TokenState::Empty | TokenState::Pending { .. }
    ));

    let act = ct_lk.account(&act_id);

    let mut state = [0u8; STATE_LEN];
    thread_rng().fill_bytes(&mut state);
    let state_str = urlencoding::encode_binary(&state).into_owned();

    let scopes_join = act.scopes.join(" ");
    let redirect_uri = act.redirect_uri(pstate.http_port)?.to_string();
    let mut params = vec![
        ("access_type", "offline"),
        ("scope", scopes_join.as_str()),
        ("client_id", act.client_id.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("response_type", "code"),
        ("state", state_str.as_str()),
    ];
    if let Some(x) = &act.login_hint {
        params.push(("login_hint", x));
    }
    let url = Url::parse_with_params(ct_lk.account(&act_id).auth_uri.as_str(), &params)?;
    ct_lk.tokenstate_replace(
        act_id,
        TokenState::Pending {
            last_notification: None,
            url,
            state,
        },
    );
    drop(ct_lk);
    pstate.notifier.notify_new(Arc::clone(&pstate));
    Ok(())
}
