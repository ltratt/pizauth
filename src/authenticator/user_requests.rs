use std::{
    error::Error,
    sync::{
        mpsc::{channel, Receiver, Sender},
        Arc, Mutex,
    },
    thread,
};

use log::warn;
use rand::{thread_rng, RngCore};
use url::Url;

use super::{AuthenticatorState, TokenState, STATE_LEN};

fn process(
    pstate: Arc<Mutex<AuthenticatorState>>,
    queue_rx: Receiver<String>,
) -> Result<(), Box<dyn Error>> {
    while let Ok(act_name) = queue_rx.recv() {
        // If unwrap()ing the lock fails, we're in such deep trouble that trying to carry on is
        // pointless.
        let mut lk = pstate.lock().unwrap();
        let mut new_token_state = None;
        let mut url = None;
        match lk.tokens.get(act_name.as_str()) {
            Some(TokenState::Empty) => {
                // lk.tokens and lk.accounts always contain the same keys so this unwrap() is safe.
                let act = lk.conf.accounts.get(act_name.as_str()).unwrap();

                let mut state = [0u8; STATE_LEN];
                thread_rng().fill_bytes(&mut state);
                let state_str = urlencoding::encode_binary(&state).into_owned();

                let scopes_join = act.scopes.join(" ");
                let redirect_uri = act.redirect_uri(lk.http_port);
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
                    lk.conf
                        .accounts
                        .get(act_name.as_str())
                        .unwrap()
                        .auth_uri
                        .as_str(),
                    &params,
                )?);
                new_token_state = Some(TokenState::Pending { state });
            }
            Some(TokenState::Pending { state: _ }) => {
                // FIXME: We might need to renew the request if it's too old.
                todo!();
            }
            Some(TokenState::Active { .. }) => {
                // FIXME: We might need to renew the request if the token has been revoked.
                todo!();
            }
            None => {
                // This account disappeared during a config reload so we just ignore it.
            }
        }
        if let Some(x) = new_token_state {
            *lk.tokens.get_mut(act_name.as_str()).unwrap() = x;
        }
        drop(lk);
        if let Some(url) = url {
            println!("{url:}");
        }
    }
    Ok(())
}

pub fn user_requests_processor(pstate: Arc<Mutex<AuthenticatorState>>) -> Sender<String> {
    let (queue_tx, queue_rx) = channel::<String>();
    thread::spawn(move || {
        if let Err(e) = process(pstate, queue_rx) {
            warn!("{e:}");
        }
    });
    queue_tx
}
