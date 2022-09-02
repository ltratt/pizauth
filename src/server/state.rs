use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};

use url::Url;

use super::{notifier::Notifier, refresher::Refresher, STATE_LEN};
use crate::{config::Config, frontends::Frontend};

pub struct AuthenticatorState {
    pub conf_tokens: Mutex<(Config, HashMap<String, TokenState>)>,
    pub http_port: u16,
    pub frontend: Arc<Box<dyn Frontend>>,
    pub notifier: Arc<Notifier>,
    pub refresher: Refresher,
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
