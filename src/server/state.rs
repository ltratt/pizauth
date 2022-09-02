use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::Instant,
};

use url::Url;

use super::{notifier::Notifier, refresher::Refresher, STATE_LEN};
use crate::{config::Config, frontends::Frontend};

pub struct AuthenticatorState {
    conf_tokens: Mutex<(Config, HashMap<String, TokenState>)>,
    pub http_port: u16,
    pub frontend: Arc<Box<dyn Frontend>>,
    pub notifier: Arc<Notifier>,
    pub refresher: Refresher,
}

impl AuthenticatorState {
    pub fn new(
        conf_tokens: (Config, HashMap<String, TokenState>),
        http_port: u16,
        frontend: Arc<Box<dyn Frontend>>,
        notifier: Arc<Notifier>,
        refresher: Refresher,
    ) -> Self {
        AuthenticatorState {
            conf_tokens: Mutex::new(conf_tokens),
            http_port,
            frontend,
            notifier,
            refresher,
        }
    }

    pub fn ct_lock(&self) -> MutexGuard<(Config, HashMap<String, TokenState>)> {
        self.conf_tokens.lock().unwrap()
    }
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
