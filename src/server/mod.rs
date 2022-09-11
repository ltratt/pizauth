mod http_server;
mod notifier;
mod refresher;
mod request_token;
mod state;

use std::{
    error::Error,
    fs,
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    sync::Arc,
    thread,
};

use log::warn;
use nix::sys::signal::{raise, Signal};

use crate::{config::Config, frontends::preferred_frontend, PIZAUTH_CACHE_SOCK_LEAF};
use notifier::Notifier;
use refresher::{update_refresher, RefreshKind};
use request_token::request_token;
use state::{AuthenticatorState, CTGuard, CTGuardAccountId, TokenState};

/// Length of the OAuth state in bytes.
const STATE_LEN: usize = 8;

pub fn sock_path(cache_path: &Path) -> PathBuf {
    let mut p = cache_path.to_owned();
    p.push(PIZAUTH_CACHE_SOCK_LEAF);
    p
}

fn request(pstate: Arc<AuthenticatorState>, mut stream: UnixStream) -> Result<(), Box<dyn Error>> {
    let mut cmd = String::new();
    stream.read_to_string(&mut cmd)?;

    match &cmd.split(' ').collect::<Vec<_>>()[..] {
        ["reload", conf_path] => {
            match Config::from_path(Path::new(conf_path)) {
                Ok(new_conf) => {
                    pstate.update_conf(new_conf);
                    stream.write_all(b"ok:")?
                }
                Err(e) => stream.write_all(format!("error:{e:}").as_bytes())?,
            }
            Ok(())
        }
        ["refresh", act_name] => {
            let ct_lk = pstate.ct_lock();
            let act_id = match ct_lk.validate_act_name(act_name) {
                Some(x) => x,
                None => {
                    drop(ct_lk);
                    stream.write_all(format!("error:No account '{act_name:}'").as_bytes())?;
                    return Ok(());
                }
            };
            match ct_lk.tokenstate(&act_id) {
                TokenState::Empty | TokenState::Pending { .. } => {
                    request_token(Arc::clone(&pstate), ct_lk, act_id)?;
                    stream.write_all(b"pending:")?;
                }
                TokenState::Active { .. } => {
                    match refresher::refresh(Arc::clone(&pstate), ct_lk, act_id)? {
                        RefreshKind::AccountOrTokenStateChanged => stream.write_all(b"error:")?,
                        RefreshKind::PermanentError(msg) => {
                            stream.write_all(format!("error:{msg:}").as_bytes())?
                        }
                        RefreshKind::Refreshed => stream.write_all(b"ok:")?,
                        RefreshKind::TransitoryError(msg) => {
                            stream.write_all(format!("error:{msg:}").as_bytes())?
                        }
                    }
                    update_refresher(pstate);
                }
            }
            Ok(())
        }
        ["showtoken", act_name] => {
            // If unwrap()ing the lock fails, we're in such deep trouble that trying to carry on is
            // pointless.
            let ct_lk = pstate.ct_lock();
            let act_id = match ct_lk.validate_act_name(act_name) {
                Some(x) => x,
                None => {
                    drop(ct_lk);
                    stream.write_all(format!("error:No account '{act_name:}'").as_bytes())?;
                    return Ok(());
                }
            };
            match ct_lk.tokenstate(&act_id) {
                TokenState::Empty => {
                    request_token(Arc::clone(&pstate), ct_lk, act_id)?;
                    stream.write_all(b"pending:")?;
                }
                TokenState::Pending {
                    last_notification: _,
                    state: _,
                    url: _,
                } => {
                    drop(ct_lk);
                    stream.write_all(b"pending:")?;
                }
                TokenState::Active {
                    access_token,
                    expiry: _,
                    refreshed_at: _,
                    refresh_token: _,
                } => {
                    let response = format!("access_token:{access_token:}");
                    drop(ct_lk);
                    stream.write_all(response.as_bytes())?;
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

    let pstate = Arc::new(AuthenticatorState::new(
        conf,
        http_port,
        Arc::clone(&frontend),
        Arc::clone(&notifier),
        refresher,
    ));

    http_server::http_server(Arc::clone(&pstate), http_state)?;
    refresher::refresher(Arc::clone(&pstate))?;
    notifier.notifier(Arc::clone(&pstate))?;

    let listener = UnixListener::bind(sock_path)?;
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let pstate = Arc::clone(&pstate);
            if let Err(e) = request(pstate, stream) {
                warn!("{e:}");
            }
        }
    });

    frontend.main_loop()?;

    Ok(())
}
