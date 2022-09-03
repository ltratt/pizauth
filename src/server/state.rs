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

    /// Lock the config and tokens and return a guard.
    ///
    /// # Panics
    ///
    /// If another thread poisoned the underlying lock, this function will panic. There is little
    /// to be done in such a case, as it is likely that pizauth is in an inconsistent, and
    /// irretrievable, state.
    pub fn ct_lock(&self) -> CTGuard {
        CTGuard {
            guard: self.conf_tokens.lock().unwrap(),
        }
    }
}

/// A lock guard around the [Config] and tokens. When this guard is dropped, the lock will be
/// released.
pub struct CTGuard<'a> {
    guard: MutexGuard<'a, (Config, HashMap<String, TokenState>)>,
}

impl<'a> CTGuard<'a> {
    pub fn config(&self) -> &Config {
        &self.guard.0
    }

    pub fn account_names(&self) -> impl Iterator<Item = &str> {
        self.guard.0.accounts.keys().map(|x| x.as_str())
    }

    pub fn account_matching_token_state(&self, state: &[u8]) -> Option<&str> {
        self.guard
            .1
            .iter()
            .find(|(_, v)| matches!(*v, &TokenState::Pending { state: s, .. } if s == state))
            .map(|(k, _)| k.as_str())
    }

    pub fn tokenstate(&self, act_name: &str) -> Option<&TokenState> {
        self.guard.1.get(act_name)
    }

    pub fn tokenstate_mut(&mut self, act_name: &str) -> Option<&mut TokenState> {
        self.guard.1.get_mut(act_name)
    }

    pub fn update(&mut self, conf_tokens: (Config, HashMap<String, TokenState>)) {
        *self.guard = conf_tokens;
    }
}

#[derive(Clone, Debug)]
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
