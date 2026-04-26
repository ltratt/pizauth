use std::{
    collections::VecDeque,
    error::Error,
    fmt::{self, Display, Formatter},
    sync::{Arc, Condvar, Mutex},
    thread,
    time::Duration,
};

use log::error;

use crate::{server::AuthenticatorState, shell_cmd::shell_cmd};

/// How long to run `token_event_cmd`s before killing them?
const TOKEN_EVENT_CMD_TIMEOUT: Duration = Duration::from_secs(10);

pub enum TokenEvent {
    Invalidated,
    New,
    Refresh,
    Revoked,
}

impl Display for TokenEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TokenEvent::Invalidated => write!(f, "token_invalidated"),
            TokenEvent::New => write!(f, "token_new"),
            TokenEvent::Refresh => write!(f, "token_refreshed"),
            TokenEvent::Revoked => write!(f, "token_revoked"),
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
                if let Err(e) = shell_cmd(
                    &token_event_cmd,
                    [
                        ("PIZAUTH_ACCOUNT", act_name.as_str()),
                        ("PIZAUTH_EVENT", &event.to_string()),
                    ],
                    TOKEN_EVENT_CMD_TIMEOUT,
                ) {
                    error!("{e}");
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
