//! This module contains pizauth's core central state. [AuthenticatorState] is the global state,
//! but mostly what one is interested in are [Account]s and [TokenState]s. These are (literally)
//! locked together: every [Account] has a [TokenState] and vice versa. However, a challenge is
//! that we allow users to reload their config at any point: we have to be very careful about
//! associating an [Account] with a [TokenState].
//!
//! To that end, we don't allow any part of pizauth outside this module to directly access
//! [Account]s or [TokenState]s: you must access it via a [CTGuard] handed to you by
//! [AuthenticatorState::ct_lock]. From a [CTGuard] you then obtain a semi-opaque
//! [CTGuardAccountId] instance which is in a sense a "version" of an [Account]. The API requires
//! you to revalidate such instances whenever you drop and reacquire a [CTGuard]: if the [Account]
//! "version" has changed, the [CTGuardAccountId] is no longer valid. This API is mildly irritating
//! to use, but guarantees that one can't do something based on an outdated idea of what the
//! configuration actually is.

use std::{
    collections::HashMap,
    rc::{Rc, Weak},
    sync::{Arc, Mutex, MutexGuard},
    time::Instant,
};

use url::Url;

use super::{notifier::Notifier, refresher::Refresher, STATE_LEN};
use crate::{
    config::{Account, Config},
    frontends::Frontend,
};

/// pizauth's global state.
pub struct AuthenticatorState {
    /// The "global lock" protecting the config and current [TokenState]s. Can only be accessed via
    /// [AuthenticatorState::ct_lock].
    conf_tokens: Mutex<(Config, HashMap<String, TokenState>)>,
    /// port of the HTTP server required by OAuth.
    pub http_port: u16,
    pub frontend: Arc<Box<dyn Frontend>>,
    pub notifier: Arc<Notifier>,
    pub refresher: Refresher,
}

impl AuthenticatorState {
    pub fn new(
        conf: Config,
        http_port: u16,
        frontend: Arc<Box<dyn Frontend>>,
        notifier: Arc<Notifier>,
        refresher: Refresher,
    ) -> Self {
        let tokens = conf
            .accounts
            .iter()
            .map(|(k, _)| (k.to_owned(), TokenState::Empty))
            .collect();
        AuthenticatorState {
            conf_tokens: Mutex::new((conf, tokens)),
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
        CTGuard::new(self.conf_tokens.lock().unwrap())
    }
}

/// A lock guard around the [Config] and tokens. When this guard is dropped:
///
///   1. the config lock will be released.
///   2. any [CTGuardAccountId] instances created from this [CTGuard] will no longer by valid
///      i.e. they will not be able to access [Account]s or [TokenState]s until they are
///      revalidated.
pub struct CTGuard<'a> {
    guard: MutexGuard<'a, (Config, HashMap<String, TokenState>)>,
    act_rc: Rc<()>,
}

impl<'a> CTGuard<'a> {
    fn new(guard: MutexGuard<'a, (Config, HashMap<String, TokenState>)>) -> CTGuard {
        CTGuard {
            guard,
            act_rc: Rc::new(()),
        }
    }

    pub fn config(&self) -> &Config {
        &self.guard.0
    }

    /// If `act_name` references a current account, return a [CTGuardAccountId].
    pub fn validate_act_name(&self, act_name: &str) -> Option<CTGuardAccountId> {
        self.guard
            .0
            .accounts
            .get(act_name)
            .map(|act| CTGuardAccountId {
                account: Arc::clone(act),
                guard_rc: Rc::downgrade(&self.act_rc),
            })
    }

    /// If `act_id` would still be a valid account under the current [CTGuard], create a new
    /// [CTGuardAccountId] which can be used in its stead. If the input `act_id` is no longer
    /// valid, return `None`.
    pub fn validate_act_id(&self, act_id: CTGuardAccountId) -> Option<CTGuardAccountId> {
        match self.guard.0.accounts.get(&act_id.account.name) {
            // We use `Arc::ptr_eq` because it's strictly stronger than `==`: it's possible for an
            // account X to be changed from having contents C to C' and back to C, and we don't
            // want to assume those two `C`s are equivalent.
            Some(act) if Arc::ptr_eq(&act_id.account, act) => Some(CTGuardAccountId {
                account: act_id.account,
                guard_rc: Rc::downgrade(&self.act_rc),
            }),
            _ => None,
        }
    }

    /// An iterator that will produce one [CTGuardAccountId] for each currently active account.
    pub fn act_ids(&self) -> impl Iterator<Item = CTGuardAccountId> + '_ {
        self.guard.0.accounts.values().map(|act| CTGuardAccountId {
            account: Arc::clone(act),
            guard_rc: Rc::downgrade(&self.act_rc),
        })
    }

    /// Return the [CTGuardAccountId] with state `state`.
    pub fn act_id_matching_token_state(&self, state: &[u8]) -> Option<CTGuardAccountId> {
        self.act_ids()
            .find(|act_id|
                matches!(self.tokenstate(act_id), &TokenState::Pending { state: s, .. } if s == state))
    }

    /// Return the [Account] for account `act_id`.
    pub fn account(&self, act_id: &CTGuardAccountId) -> &Account {
        if Weak::strong_count(&act_id.guard_rc) != 1 {
            panic!("CTGuardAccountId has outlived its parent CTGuard.");
        }
        self.guard.0.accounts.get(&act_id.account.name).unwrap()
    }

    /// Return a reference to the [TokenState] of `act_id`. The user must have validated `act_id`
    /// under the current [CTGuard].
    ///
    /// # Panics
    ///
    /// If `act_id` has outlived its parent [CTGuard].
    pub fn tokenstate(&self, act_id: &CTGuardAccountId) -> &TokenState {
        if Weak::strong_count(&act_id.guard_rc) != 1 {
            panic!("CTGuardAccountId has outlived its parent CTGuard.");
        }
        self.guard.1.get(&act_id.account.name).unwrap()
    }

    /// Return a mutable reference to the [TokenState] of `act_id`. The user must have validated
    /// `act_id` under the current [CTGuard].
    ///
    /// # Panics
    ///
    /// If `act_id` has outlived its parent [CTGuard].
    pub fn tokenstate_mut(&mut self, act_id: &CTGuardAccountId) -> &mut TokenState {
        if Weak::strong_count(&act_id.guard_rc) != 1 {
            panic!("CTGuardAccountId has outlived its parent CTGuard.");
        }
        self.guard.1.get_mut(&act_id.account.name).unwrap()
    }

    pub fn update(&mut self, conf_tokens: (Config, HashMap<String, TokenState>)) {
        *self.guard = conf_tokens;
    }
}

/// An opaque account identifier, only fully valid while the [CTGuard] it was created from is not
/// dropped. While the [CTGuardAccountId] is valid, it can be used to lookup [Account]s and
/// [TokenState]s without further validity checks. After the [CTGuard] it was created from is
/// dropped, one cannot use a `CTGuardAccountId` to query token states (etc.), but can use it to
/// compare whether an old and a new `CTGuardAccountId` reference the same underlying [Account].
pub struct CTGuardAccountId {
    account: Arc<Account>,
    guard_rc: Weak<()>,
}

#[derive(Clone, Debug)]
pub enum TokenState {
    /// Authentication is neither pending nor active.
    Empty,
    /// Pending authentication
    Pending {
        last_notification: Option<Instant>,
        state: [u8; STATE_LEN],
        url: Url,
    },
    /// There is an active token (and, possibly, also an active refresh token).
    Active {
        access_token: String,
        refreshed_at: Instant,
        expiry: Instant,
        refresh_token: Option<String>,
    },
}
