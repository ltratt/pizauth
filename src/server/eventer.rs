use std::{
    collections::VecDeque,
    env,
    error::Error,
    fmt::{self, Display, Formatter},
    process::Command,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::Duration,
};

use log::error;
use wait_timeout::ChildExt;

use super::AuthenticatorState;

/// How long to run `not_transient_error_if` commands before killing them?
const NEW_ACCESS_TOKEN_CMD_TIMEOUT: Duration = Duration::from_secs(30);

pub enum TokenEvent {
    Invalidated,
    New,
    Refresh,
}

impl Display for TokenEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TokenEvent::Invalidated => write!(f, "token_invalidated"),
            TokenEvent::New => write!(f, "token_new"),
            TokenEvent::Refresh => write!(f, "token_refreshed"),
        }
    }
}

pub struct Eventer {
    pred: Mutex<bool>,
    condvar: Condvar,
    event_queue: Mutex<VecDeque<(String, TokenEvent)>>,
}

impl Eventer {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        Ok(Eventer {
            pred: Mutex::new(false),
            condvar: Condvar::new(),
            event_queue: Mutex::new(VecDeque::new()),
        })
    }

    pub fn eventer(self: Arc<Self>, pstate: Arc<AuthenticatorState>) -> Result<(), Box<dyn Error>> {
        thread::spawn(move || loop {
            let mut eventer_lk = self.pred.lock().unwrap();
            while !*eventer_lk {
                eventer_lk = self.condvar.wait(eventer_lk).unwrap();
            }
            *eventer_lk = false;
            drop(eventer_lk);

            loop {
                let (act_name, event) =
                    if let Some((act_name, event)) = self.event_queue.lock().unwrap().pop_front() {
                        (act_name, event)
                    } else {
                        break;
                    };
                let token_event_cmd = if let Some(token_event_cmd) =
                    pstate.ct_lock().config().token_event_cmd.clone()
                {
                    token_event_cmd
                } else {
                    break;
                };
                match env::var("SHELL") {
                    Ok(s) => {
                        match Command::new(s)
                            .env("PIZAUTH_ACCOUNT", act_name.as_str())
                            .env("PIZAUTH_EVENT", &format!("{event}"))
                            .args(["-c", &token_event_cmd])
                            .spawn()
                        {
                            Ok(mut child) => match child.wait_timeout(NEW_ACCESS_TOKEN_CMD_TIMEOUT)
                            {
                                Ok(Some(status)) => {
                                    if !status.success() {
                                        error!(
                                            "'{token_event_cmd:}' returned {}",
                                            status
                                                .code()
                                                .map(|x| x.to_string())
                                                .unwrap_or_else(|| "<Unknown exit code".to_string())
                                        );
                                    }
                                }
                                Ok(None) => {
                                    child.kill().ok();
                                    child.wait().ok();
                                    error!("'{token_event_cmd:}' exceeded timeout");
                                }
                                Err(e) => error!("Waiting on '{token_event_cmd:}' failed: {e:}"),
                            },
                            Err(e) => error!("Couldn't execute '{token_event_cmd:}': {e:}"),
                        }
                    }
                    Err(e) => error!("{e:}"),
                }
            }
        });

        Ok(())
    }

    pub fn token_event(&self, act_name: String, kind: TokenEvent) {
        self.event_queue.lock().unwrap().push_back((act_name, kind));
        let mut event_lk = self.pred.lock().unwrap();
        *event_lk = true;
        self.condvar.notify_one();
    }
}
