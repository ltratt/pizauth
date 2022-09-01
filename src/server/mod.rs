mod http_server;
mod notifier;
mod refresher;
mod request_token;
mod user_listener;

use std::{
    collections::HashMap,
    error::Error,
    fs,
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    sync::{mpsc::Sender, Arc, Mutex},
    thread,
    time::Instant,
};

use log::warn;
use nix::sys::signal::{raise, Signal};
use url::Url;

use crate::{
    config::Config,
    frontends::{preferred_frontend, Frontend},
    PIZAUTH_CACHE_SOCK_LEAF,
};
use notifier::Notifier;
use refresher::{update_refresher, Refresher};

/// Length of the OAuth state in bytes.
const STATE_LEN: usize = 8;

pub fn sock_path(cache_path: &Path) -> PathBuf {
    let mut p = cache_path.to_owned();
    p.push(PIZAUTH_CACHE_SOCK_LEAF);
    p
}

pub struct AuthenticatorState {
    conf_tokens: Mutex<(Config, HashMap<String, TokenState>)>,
    http_port: u16,
    frontend: Arc<Box<dyn Frontend>>,
    notifier: Arc<Notifier>,
    refresher: Refresher,
}

#[derive(Debug)]
pub enum TokenState {
    Empty,
    /// Pending authentication
    Pending {
        last_notification: Option<Instant>,
        state: [u8; STATE_LEN],
        url: Url,
    },
    Active {
        access_token: String,
        refreshed_at: Instant,
        expiry: Instant,
        refresh_token: Option<String>,
    },
}

fn request(
    pstate: Arc<AuthenticatorState>,
    mut stream: UnixStream,
    queue_tx: Sender<String>,
) -> Result<(), Box<dyn Error>> {
    let mut cmd = String::new();
    stream.read_to_string(&mut cmd)?;

    match &cmd.split(' ').collect::<Vec<_>>()[..] {
        ["reload", conf_path] => {
            match user_listener::reload_conf(pstate, conf_path) {
                Ok(()) => stream.write_all(b"ok:")?,
                Err(e) => stream.write_all(format!("error:{e:}").as_bytes())?,
            }
            Ok(())
        }
        ["refresh", act] => {
            let ct_lk = pstate.conf_tokens.lock().unwrap();
            match ct_lk.1.get(act.to_owned()) {
                Some(TokenState::Empty) | Some(TokenState::Pending { .. }) => {
                    drop(ct_lk);
                    queue_tx.send(act.to_string())?;
                    stream.write_all(b"ok:")?;
                }
                Some(TokenState::Active { .. }) => {
                    drop(ct_lk);
                    refresher::refresh(Arc::clone(&pstate), act.to_string())?;
                    update_refresher(pstate);
                    stream.write_all(b"ok:")?;
                }
                None => {
                    drop(ct_lk);
                    stream.write_all(format!("error:No account '{act:}'").as_bytes())?;
                }
            }
            Ok(())
        }
        ["showtoken", act] => {
            // If unwrap()ing the lock fails, we're in such deep trouble that trying to carry on is
            // pointless.
            let ct_lk = pstate.conf_tokens.lock().unwrap();
            match ct_lk.1.get(act.to_owned()) {
                Some(TokenState::Empty) => {
                    drop(ct_lk);
                    queue_tx.send(act.to_string())?;
                    stream.write_all(b"pending:")?;
                }
                Some(TokenState::Pending {
                    last_notification: _,
                    state: _,
                    url: _,
                }) => {
                    drop(ct_lk);
                    stream.write_all(b"pending:")?;
                }
                Some(TokenState::Active {
                    access_token,
                    expiry: _,
                    refreshed_at: _,
                    refresh_token: _,
                }) => {
                    let response = format!("access_token:{access_token:}");
                    drop(ct_lk);
                    stream.write_all(response.as_bytes())?;
                }
                None => {
                    drop(ct_lk);
                    stream.write_all(format!("error:No account '{act:}'").as_bytes())?;
                }
            }
            Ok(())
        }
        ["shutdown"] => {
            raise(Signal::SIGTERM).ok();
            Ok(())
        }
        _ => Err(format!("Invalid cmd '{cmd:}'").into()),
    }
}

pub fn server(conf: Config, cache_path: &Path) -> Result<(), Box<dyn Error>> {
    let sock_path = sock_path(cache_path);
    if sock_path.exists() {
        // Is an existing authenticator running?
        if UnixStream::connect(&sock_path).is_ok() {
            return Err("pizauth authenticator already running".into());
        }
        fs::remove_file(&sock_path).ok();
    }

    let (http_port, http_state) = http_server::http_server_setup()?;
    let frontend = Arc::new(preferred_frontend()?);
    let notifier = Arc::new(Notifier::new()?);
    let refresher = refresher::refresher_setup()?;

    let tokens = conf
        .accounts
        .iter()
        .map(|(k, _)| (k.to_owned(), TokenState::Empty))
        .collect();
    let pstate = Arc::new(AuthenticatorState {
        conf_tokens: Mutex::new((conf, tokens)),
        http_port,
        frontend: Arc::clone(&frontend),
        notifier: Arc::clone(&notifier),
        refresher,
    });

    let user_req_tx = request_token::request_token_processor(Arc::clone(&pstate));
    http_server::http_server(Arc::clone(&pstate), http_state)?;
    refresher::refresher(Arc::clone(&pstate))?;
    notifier.notifier(Arc::clone(&pstate))?;

    let listener = UnixListener::bind(sock_path)?;
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let pstate = Arc::clone(&pstate);
            let user_req_tx = Sender::clone(&user_req_tx);
            if let Err(e) = request(pstate, stream, user_req_tx) {
                warn!("{e:}");
            }
        }
    });

    frontend.main_loop()?;

    Ok(())
}
