use std::{error::Error, sync::Arc};

use rand::{thread_rng, RngCore};
use sha2::{Digest, Sha256};
use url::Url;

use super::{AccountId, AuthenticatorState, CTGuard, TokenState, CODE_VERIFIER_LEN, STATE_LEN};

/// Request a new token for `act_id`, whose tokenstate must be `Empty`.
pub fn request_token(
    pstate: Arc<AuthenticatorState>,
    mut ct_lk: CTGuard,
    act_id: AccountId,
) -> Result<Url, Box<dyn Error>> {
    assert!(matches!(
        ct_lk.tokenstate(act_id),
        TokenState::Empty | TokenState::Pending { .. }
    ));

    let act = ct_lk.account(act_id);

    let mut state = [0u8; STATE_LEN];
    thread_rng().fill_bytes(&mut state);
    let state = base64::encode_config(
        state,
        base64::Config::new(base64::CharacterSet::UrlSafe, false),
    );

    let mut code_verifier = [0u8; CODE_VERIFIER_LEN];
    thread_rng().fill_bytes(&mut code_verifier);
    let code_verifier = base64::encode_config(
        &code_verifier,
        base64::Config::new(base64::CharacterSet::UrlSafe, false),
    );
    let mut hasher = Sha256::new();
    hasher.update(&code_verifier);
    let code_challenge = base64::encode_config(
        hasher.finalize(),
        base64::Config::new(base64::CharacterSet::UrlSafe, false),
    );

    let scopes_join = act.scopes.join(" ");
    let redirect_uri = act.redirect_uri(pstate.http_port)?.to_string();
    let mut params = vec![
        ("access_type", "offline"),
        ("code_challenge", &code_challenge),
        ("code_challenge_method", "S256"),
        ("scope", scopes_join.as_str()),
        ("client_id", act.client_id.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("response_type", "code"),
        ("state", &state),
    ];
    if let Some(x) = &act.login_hint {
        params.push(("login_hint", x));
    }
    let url = Url::parse_with_params(ct_lk.account(act_id).auth_uri.as_str(), &params)?;
    ct_lk.tokenstate_replace(
        act_id,
        TokenState::Pending {
            code_verifier,
            last_notification: None,
            url: url.clone(),
            state,
        },
    );
    drop(ct_lk);
    pstate.notifier.notify_changes();
    Ok(url)
}
