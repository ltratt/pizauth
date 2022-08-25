use std::{
    error::Error,
    sync::{
        mpsc::{channel, Receiver, Sender},
        Arc,
    },
    thread,
};

use log::warn;
use rand::{thread_rng, RngCore};
use url::Url;

use super::{AuthenticatorState, TokenState, STATE_LEN};

fn process(
    pstate: Arc<AuthenticatorState>,
    queue_rx: Receiver<String>,
) -> Result<(), Box<dyn Error>> {
    while let Ok(act_name) = queue_rx.recv() {
        // If unwrap()ing the lock fails, we're in such deep trouble that trying to carry on is
        // pointless.
        let mut ct_lk = pstate.conf_tokens.lock().unwrap();
        let mut new_token_state = None;
        let mut url = None;
        match ct_lk.1.get(act_name.as_str()) {
            Some(_) => {
                // lk.tokens and lk.accounts always contain the same keys so this unwrap() is safe.
                let act = ct_lk.0.accounts.get(act_name.as_str()).unwrap();

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
                url = Some(Url::parse_with_params(
                    ct_lk
                        .0
                        .accounts
                        .get(act_name.as_str())
                        .unwrap()
                        .auth_uri
                        .as_str(),
                    &params,
                )?);
                new_token_state = Some(TokenState::Pending { state });
            }
            None => {
                // This account disappeared during a config reload so we just ignore it.
            }
        }
        if let Some(x) = new_token_state {
            *ct_lk.1.get_mut(act_name.as_str()).unwrap() = x;
        }
        drop(ct_lk);
        if let Some(url) = url {
            println!("{url:}");
        }
    }
    Ok(())
}

pub fn request_token_processor(pstate: Arc<AuthenticatorState>) -> Sender<String> {
    let (queue_tx, queue_rx) = channel::<String>();
    thread::spawn(move || {
        if let Err(e) = process(pstate, queue_rx) {
            warn!("{e:}");
        }
    });
    queue_tx
}
