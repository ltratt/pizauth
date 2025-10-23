mod eventer;
mod http_server;
mod notifier;
mod refresher;
mod request_token;
mod state;

use std::{
    collections::HashMap,
    env,
    error::Error,
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    thread,
    time::{Duration, SystemTime},
};

use boot_time::Instant;
use chrono::{DateTime, Local};
use log::{error, warn};
use nix::sys::signal::{raise, Signal};
#[cfg(target_os = "openbsd")]
use pledge::pledge;
#[cfg(target_os = "openbsd")]
use unveil::unveil;

use crate::{config::Config, PIZAUTH_CACHE_SOCK_LEAF};
use eventer::{Eventer, TokenEvent};
use notifier::Notifier;
use refresher::Refresher;
use request_token::request_token;
use serde_json::json;
use state::{AccountId, AuthenticatorState, CTGuard, TokenState};

/// Length of the PKCE code verifier in bytes.
const CODE_VERIFIER_LEN: usize = 64;
/// The timeout for ureq HTTP requests. It is recommended to make this value lower than
/// REFRESH_RETRY_DEFAULT to reduce the likelihood that refresh requests overlap.
pub const UREQ_TIMEOUT: Duration = Duration::from_secs(30);
/// Length of the OAuth state in bytes.
const STATE_LEN: usize = 8;
/// When waiting to do something (e.g. in the notifier or refresher), we have the problem that when
/// we ask to be woken up in "X seconds from now", operating systems do not interpret that as "wake
/// you up in X seconds of wall-clock time". For example, if a machine is suspended then resumed,
/// then the time the machine was out of action may not be counted as "wait time". The impact of
/// ntp/adjtime and friends is also unclear. There is no portable way for us to know if any of
/// these things has happened, so we are left in the unhappy situation that if a thread knows it
/// has work to do in the future, it needs to wake itself up every so often to check if -- without
/// us knowing it! -- the clock has changed underneath it.
///
/// There is no universally good value here. Too short means that we waste resources; too long and
/// the user will think that we have gone wrong; too predictable and we might end up causing weird
/// spikes in performance (e.g. if we wake up exactly every 10/30/60 seconds). To make problems
/// even less likely, we choose a prime number.
const MAX_WAIT_SECS: u64 = 37;

pub fn sock_path(cache_path: &Path) -> PathBuf {
    let mut p = cache_path.to_owned();
    p.push(PIZAUTH_CACHE_SOCK_LEAF);
    p
}

/// Calculate the [Instant] that a token will expire at. Returns `Err` if [Instant] cannot
/// represent the expiry.
pub fn expiry_instant(
    ct_lk: &CTGuard,
    act_id: AccountId,
    refreshed_at: Instant,
    expires_in: u64,
) -> Result<Instant, Box<dyn Error>> {
    refreshed_at
        .checked_add(Duration::from_secs(expires_in))
        .or_else(|| {
            refreshed_at.checked_add(ct_lk.account(act_id).refresh_at_least(ct_lk.config()))
        })
        .ok_or_else(|| "Can't represent expiry".into())
}

fn request(pstate: Arc<AuthenticatorState>, mut stream: UnixStream) -> Result<(), Box<dyn Error>> {
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let (cmd, rest) = {
        let len = buf
            .iter()
            .map(|b| *b as char)
            .take_while(|c| *c != ':')
            .count();
        if len == buf.len() {
            return Err(format!(
                "Syntactically invalid request '{}'",
                std::str::from_utf8(&buf).unwrap_or("<can't represent as UTF-8")
            )
            .into());
        }
        (std::str::from_utf8(&buf[..len])?, &buf[len + 1..])
    };

    match cmd {
        "dump" if rest.is_empty() => {
            stream.write_all(&pstate.dump()?)?;
            return Ok(());
        }
        "info" if rest.is_empty() => {
            let mut m = HashMap::new();
            m.insert(
                "http_port",
                match pstate.http_port {
                    Some(x) => x.to_string(),
                    None => "none".to_string(),
                },
            );
            m.insert(
                "https_port",
                match pstate.https_port {
                    Some(x) => x.to_string(),
                    None => "none".to_string(),
                },
            );
            if let Some(x) = &pstate.https_pub_key {
                m.insert("https_pub_key", x.clone());
            }
            stream.write_all(json!(m).to_string().as_bytes())?;
            return Ok(());
        }
        "reload" if rest.is_empty() => {
            match Config::from_path(&pstate.conf_path) {
                Ok(new_conf) => {
                    pstate.update_conf(new_conf);
                    stream.write_all(b"ok:")?
                }
                Err(e) => stream.write_all(format!("error:{e:}").as_bytes())?,
            }
            return Ok(());
        }
        "refresh" => {
            let rest = std::str::from_utf8(rest)?;
            if let [with_url, act_name] = &rest.splitn(2, ' ').collect::<Vec<_>>()[..] {
                let ct_lk = pstate.ct_lock();
                let act_id = match ct_lk.validate_act_name(act_name) {
                    Some(x) => x,
                    None => {
                        drop(ct_lk);
                        stream.write_all(format!("error:No account '{act_name:}'").as_bytes())?;
                        return Ok(());
                    }
                };
                match ct_lk.tokenstate(act_id) {
                    TokenState::Empty | TokenState::Pending { .. } => {
                        let url = request_token(Arc::clone(&pstate), ct_lk, act_id)?;
                        if *with_url == "withurl" {
                            stream.write_all(format!("pending:{url:}").as_bytes())?;
                        } else {
                            stream.write_all(b"pending:")?;
                        }
                    }
                    TokenState::Active { .. } => {
                        drop(ct_lk);
                        pstate.refresher.sched_refresh(Arc::clone(&pstate), act_id);
                        stream.write_all(b"scheduled:")?;
                    }
                }
                return Ok(());
            }
        }
        "restore" => {
            match pstate.restore(rest.to_vec()) {
                Ok(_) => stream.write_all(b"ok:")?,
                Err(e) => stream.write_all(format!("error:{e:}").as_bytes())?,
            }
            return Ok(());
        }
        "revoke" => {
            let act_name = std::str::from_utf8(rest)?;
            let mut ct_lk = pstate.ct_lock();
            match ct_lk.validate_act_name(act_name) {
                Some(act_id) => {
                    ct_lk.tokenstate_replace(act_id, TokenState::Empty);
                    drop(ct_lk);

                    pstate
                        .eventer
                        .token_event(act_name.to_owned(), TokenEvent::Revoked);
                    stream.write_all(b"ok:")?;
                    return Ok(());
                }
                None => {
                    drop(ct_lk);
                    stream.write_all(format!("error:No account '{act_name:}'").as_bytes())?;
                    return Ok(());
                }
            };
        }
        "showtoken" => {
            let rest = std::str::from_utf8(rest)?;
            if let [with_url, act_name] = &rest.splitn(2, ' ').collect::<Vec<_>>()[..] {
                let ct_lk = pstate.ct_lock();
                let act_id = match ct_lk.validate_act_name(act_name) {
                    Some(x) => x,
                    None => {
                        drop(ct_lk);
                        stream.write_all(format!("error:No account '{act_name:}'").as_bytes())?;
                        return Ok(());
                    }
                };
                match ct_lk.tokenstate(act_id) {
                    TokenState::Empty => {
                        let url = request_token(Arc::clone(&pstate), ct_lk, act_id)?;
                        if *with_url == "withurl" {
                            stream.write_all(format!("pending:{url:}").as_bytes())?;
                        } else {
                            stream.write_all(b"pending:")?;
                        }
                    }
                    TokenState::Pending { ref url, .. } => {
                        let response = if *with_url == "withurl" {
                            format!("pending:{url:}")
                        } else {
                            "pending:".to_owned()
                        };
                        drop(ct_lk);
                        stream.write_all(response.as_bytes())?;
                    }
                    TokenState::Active {
                        access_token,
                        access_token_expiry,
                        ongoing_refresh,
                        ..
                    } => {
                        let response = if access_token_expiry > &Instant::now() {
                            format!("access_token:{access_token:}")
                        } else if *ongoing_refresh {
                            "error:Access token has expired. Refreshing is in progress but has not yet succeeded"
                                .into()
                        } else {
                            pstate.refresher.sched_refresh(Arc::clone(&pstate), act_id);
                            "error:Access token has expired. Refreshing initiated".into()
                        };
                        drop(ct_lk);
                        stream.write_all(response.as_bytes())?;
                    }
                }
                return Ok(());
            }
        }
        "shutdown" if rest.is_empty() => {
            raise(Signal::SIGTERM).ok();
            return Ok(());
        }
        "status" if rest.is_empty() => {
            let ct_lk = pstate.ct_lock();
            let mut acts = Vec::new();
            for act_id in ct_lk.act_ids() {
                let act = ct_lk.account(act_id);
                let st = match ct_lk.tokenstate(act_id) {
                    TokenState::Empty => "No access token".into(),
                    TokenState::Pending {
                        last_notification: Some(i),
                        ..
                    } => format!(
                        "Access token pending authentication (last notification {})",
                        instant_fmt(*i)
                    ),
                    TokenState::Pending {
                        last_notification: None,
                        ..
                    } => "Access token pending authentication".into(),
                    TokenState::Active {
                        access_token_obtained,
                        access_token_expiry,
                        last_refresh_attempt,
                        ..
                    } => {
                        if *access_token_expiry > Instant::now() {
                            format!(
                                "Active access token (obtained {}; expires {})",
                                instant_fmt(*access_token_obtained),
                                instant_fmt(*access_token_expiry)
                            )
                        } else if let Some(i) = last_refresh_attempt {
                            format!(
                                "Access token expired (last refresh attempt {})",
                                instant_fmt(*i)
                            )
                        } else {
                            "Access token expired (refresh not yet attempted)".into()
                        }
                    }
                };
                acts.push(format!("{}: {st}", act.name));
            }
            acts.sort();
            if acts.is_empty() {
                stream.write_all(b"error:No accounts configured")?;
            } else {
                stream.write_all(format!("ok:{}", acts.join("\n")).as_bytes())?;
            }
            return Ok(());
        }
        x => stream.write_all(format!("error:Unknown command '{x}'").as_bytes())?,
    }
    Err("Invalid command".into())
}

/// Attempt to print an [Instant] as a user-readable string. By the very nature of [Instant]s,
/// there is no guarantee this is possible or that the time presented is accurate.
fn instant_fmt(i: Instant) -> String {
    let now = Instant::now();
    if i < now {
        if let Some(d) = now.checked_duration_since(i) {
            if let Some(st) = SystemTime::now().checked_sub(d) {
                let dt: DateTime<Local> = st.into();
                return dt.to_rfc2822();
            }
        }
    } else if let Some(d) = i.checked_duration_since(now) {
        if let Some(st) = SystemTime::now().checked_add(d) {
            let dt: DateTime<Local> = st.into();
            return dt.to_rfc2822();
        }
    }
    "<unknown time>".into()
}

/// If [Config::startup_cmd] is non-`None`, call this function to run that command (in a thread, so
/// this is non-blocking).
fn startup_cmd(cmd: String) {
    thread::spawn(move || match env::var("SHELL") {
        Ok(s) => match Command::new(s).args(["-c", &cmd]).spawn() {
            Ok(mut child) => match child.wait() {
                Ok(status) => {
                    if !status.success() {
                        error!(
                            "'{cmd:}' returned {}",
                            status
                                .code()
                                .map(|x| x.to_string())
                                .unwrap_or_else(|| "<Unknown exit code".to_string())
                        );
                    }
                }
                Err(e) => error!("Waiting on '{cmd:}' failed: {e:}"),
            },
            Err(e) => error!("Couldn't execute '{cmd:}': {e:}"),
        },
        Err(e) => error!("{e:}"),
    });
}

pub fn server(conf_path: PathBuf, conf: Config, cache_path: &Path) -> Result<(), Box<dyn Error>> {
    let sock_path = sock_path(cache_path);

    #[cfg(target_os = "openbsd")]
    unveil(
        conf_path
            .as_os_str()
            .to_str()
            .ok_or("Cannot use configuration path in unveil")?,
        "rx",
    )?;
    #[cfg(target_os = "openbsd")]
    unveil(
        sock_path
            .as_os_str()
            .to_str()
            .ok_or("Cannot use socket path in unveil")?,
        "rwxc",
    )?;
    #[cfg(target_os = "openbsd")]
    unveil(std::env::var("SHELL")?, "rx")?;
    #[cfg(target_os = "openbsd")]
    unveil("/dev/random", "rx")?;
    #[cfg(target_os = "openbsd")]
    unveil("", "")?;

    #[cfg(target_os = "openbsd")]
    pledge("stdio rpath wpath inet fattr unix dns proc exec", None).unwrap();

    let (http_port, http_state) = match http_server::http_server_setup(&conf)? {
        Some((x, y)) => (Some(x), Some(y)),
        None => (None, None),
    };
    let (https_port, https_state, certified_key) = match http_server::https_server_setup(&conf)? {
        Some((x, y, z)) => (Some(x), Some(y), Some(z)),
        None => (None, None, None),
    };
    // TODO: Store certificate into trusted folder (OS dependent..)?

    let eventer = Arc::new(Eventer::new()?);
    let notifier = Arc::new(Notifier::new()?);
    let refresher = Refresher::new();

    let pub_key_str = certified_key.as_ref().map(|x| {
        x.key_pair
            .public_key_raw()
            .iter()
            .map(|x| format!("{x:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    });

    let pstate = Arc::new(AuthenticatorState::new(
        conf_path,
        conf,
        http_port,
        https_port,
        pub_key_str,
        Arc::clone(&eventer),
        Arc::clone(&notifier),
        Arc::clone(&refresher),
    ));

    if let Some(x) = http_state {
        http_server::http_server(Arc::clone(&pstate), x)?;
    }
    if let (Some(x), Some(y)) = (https_state, certified_key) {
        http_server::https_server(Arc::clone(&pstate), x, y)?;
    }
    eventer.eventer(Arc::clone(&pstate))?;
    refresher.refresher(Arc::clone(&pstate))?;
    notifier.notifier(Arc::clone(&pstate))?;

    let listener = UnixListener::bind(sock_path)?;
    if let Some(s) = &pstate.ct_lock().config().startup_cmd {
        startup_cmd(s.to_owned());
    }
    for stream in listener.incoming().flatten() {
        let pstate = Arc::clone(&pstate);
        if let Err(e) = request(pstate, stream) {
            warn!("{e:}");
        }
    }

    Ok(())
}
