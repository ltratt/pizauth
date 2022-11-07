//! This module contains pizauth's core central state. [AuthenticatorState] is the global state,
//! but mostly what one is interested in are [Account]s and [TokenState]s. These are (literally)
//! locked together: every [Account] has a [TokenState] and vice versa. However, a challenge is
//! that we allow users to reload their config at any point: we have to be very careful about
//! associating an [Account] with a [TokenState].
//!
//! To that end, we don't allow any part of pizauth outside this module to directly access
//! [Account]s or [TokenState]s: you must access it via a [CTGuard] handed to you by
//! [AuthenticatorState::ct_lock]. From a [CTGuard] you then obtain a semi-opaque
//! [AccountId] instance which is in a sense a "version" of an [Account]. The API requires
//! you to revalidate such instances whenever you drop and reacquire a [CTGuard]: if the [Account]
//! "version" has changed, the [AccountId] is no longer valid. This API is mildly irritating
//! to use, but guarantees that one can't do something based on an outdated idea of what the
//! configuration actually is.

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::Instant,
};

use url::Url;

use super::{notifier::Notifier, refresher::Refresher};
use crate::config::{Account, Config};

/// pizauth's global state.
pub struct AuthenticatorState {
    pub conf_path: PathBuf,
    /// The "global lock" protecting the config and current [TokenState]s. Can only be accessed via
    /// [AuthenticatorState::ct_lock].
    locked_state: Mutex<LockedState>,
    /// port of the HTTP server required by OAuth.
    pub http_port: u16,
    pub notifier: Arc<Notifier>,
    pub refresher: Arc<Refresher>,
}

impl AuthenticatorState {
    pub fn new(
        conf_path: PathBuf,
        conf: Config,
        http_port: u16,
        notifier: Arc<Notifier>,
        refresher: Arc<Refresher>,
    ) -> Self {
        AuthenticatorState {
            conf_path,
            locked_state: Mutex::new(LockedState::new(conf)),
            http_port,
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
        CTGuard::new(self.locked_state.lock().unwrap())
    }

    /// Update the global [Config] to `new_conf`. This cannot fail, but note that there is no
    /// guarantee that by the time this function calls the configuration is still the same as
    /// `new_conf` since another thread(s) may also have called this function.
    pub fn update_conf(&self, new_conf: Config) {
        let mut lk = self.locked_state.lock().unwrap();
        lk.update_conf(new_conf);
    }
}

/// An invariant "I1" that must be maintained at all times is that the set of keys in
/// `LockedState.config.Config.accounts` must exactly equal `LockedState.tokenstates`. This
/// invariant is relied upon by a number of `unwrap` calls which assume that if a key `x` was found
/// in one of these sets it is guaranteed to be found in the other.
struct LockedState {
    account_count: u128,
    config: Config,
    account_map: HashMap<String, AccountId>,
    tokenstates: HashMap<AccountId, TokenState>,
}

impl LockedState {
    fn new(config: Config) -> Self {
        let mut account_map = HashMap::with_capacity(config.accounts.len());
        let mut tokenstates = HashMap::with_capacity(config.accounts.len());

        let mut account_count = 0;
        for act_name in config.accounts.keys() {
            let act_id = AccountId { id: account_count };
            account_count += 1;
            account_map.insert(act_name.to_owned(), act_id);
            tokenstates.insert(act_id, TokenState::Empty);
        }

        LockedState {
            account_count,
            config,
            account_map,
            tokenstates,
        }
    }

    fn update_conf(&mut self, config: Config) {
        let mut account_map = HashMap::with_capacity(config.accounts.len());
        let mut tokenstates = HashMap::with_capacity(config.accounts.len());

        for act_name in config.accounts.keys() {
            if let Some(old_act) = self.config.accounts.get(act_name) {
                let new_act = &config.accounts[act_name];
                if new_act == old_act {
                    let act_id = self.account_map[act_name];
                    account_map.insert(act_name.to_owned(), act_id);
                    tokenstates.insert(
                        self.account_map[act_name].clone(),
                        self.tokenstates[&act_id].clone(),
                    );
                } else {
                    // The two accounts are not the same so we can't reuse the existing tokenstate,
                    // instead keeping it as Empty. However, we need to increment the version
                    // number, because there could be a very long-running thread that started
                    // acting on an Empty tokenstate, did something (very slowly), and now wants to
                    // update its status, even though multiple other updates have happened in the
                    // interim. Incrementing the version implicitly invalidates whatever (slow...)
                    // calculation it has performed.
                    let act_id = AccountId::new(self);
                    account_map.insert(act_name.to_owned(), act_id);
                    tokenstates.insert(act_id, TokenState::Empty);
                }
            } else {
                let act_id = AccountId::new(self);
                account_map.insert(act_name.to_owned(), act_id);
                tokenstates.insert(act_id, TokenState::Empty);
            }
        }

        self.account_map = account_map;
        self.tokenstates = tokenstates;
        self.config = config;

        debug_assert_eq!(
            HashSet::<&String>::from_iter(self.config.accounts.keys()),
            HashSet::from_iter(self.account_map.keys()),
        );
    }
}

/// A lock guard around the [Config] and tokens. When this guard is dropped:
///
///   1. the config lock will be released.
///   2. any [AccountId] instances created from this [CTGuard] will no longer by valid
///      i.e. they will not be able to access [Account]s or [TokenState]s until they are
///      revalidated.
pub struct CTGuard<'a> {
    guard: MutexGuard<'a, LockedState>,
}

impl<'a> CTGuard<'a> {
    fn new(guard: MutexGuard<'a, LockedState>) -> CTGuard {
        CTGuard { guard }
    }

    pub fn config(&self) -> &Config {
        &self.guard.config
    }

    /// If `act_name` references a current account, return a [AccountId].
    pub fn validate_act_name(&self, act_name: &str) -> Option<AccountId> {
        self.guard.account_map.get(act_name).cloned()
    }

    /// Is `act_id` still a valid [AccountId]?
    pub fn is_act_id_valid(&self, act_id: AccountId) -> bool {
        self.guard.tokenstates.contains_key(&act_id)
    }

    /// An iterator that will produce one [AccountId] for each currently active account.
    pub fn act_ids(&self) -> impl Iterator<Item = AccountId> + '_ {
        self.guard.account_map.values().cloned()
    }

    /// Return the [AccountId] with state `state`.
    pub fn act_id_matching_token_state(&self, state: &str) -> Option<AccountId> {
        self.guard
            .tokenstates
            .iter()
            .find(|(_, v)| matches!(v, TokenState::Pending { state: s, .. } if s == state))
            .map(|(act_id, _ts)| *act_id)
    }

    /// Return the [Account] for account `act_id`.
    pub fn account(&self, act_id: AccountId) -> &Account {
        // XXX potentially unsound unwrap!
        let act_name = self
            .guard
            .account_map
            .iter()
            .find(|(_k, v)| **v == act_id)
            .map(|(k, _v)| k)
            .unwrap();
        &*self.guard.config.accounts[act_name]
    }

    /// Return a reference to the [TokenState] of `act_id`. The user must have validated `act_id`
    /// under the current [CTGuard].
    ///
    /// # Panics
    ///
    /// If `act_id` has outlived its parent [CTGuard].
    pub fn tokenstate(&self, act_id: AccountId) -> &TokenState {
        &self.guard.tokenstates[&act_id]
    }

    /// Update the tokenstate for `act_id` to `new_tokenstate` returning a new [AccountId]
    /// valid for the new tokenstate, updating the tokenstate version.
    ///
    /// # Panics
    ///
    /// If `act_id` has outlived its parent [CTGuard].
    pub fn tokenstate_replace(
        &mut self,
        act_id: AccountId,
        new_tokenstate: TokenState,
    ) -> AccountId {
        let new_id = AccountId::new(&mut self.guard);
        for v in self.guard.account_map.values_mut() {
            if *v == act_id {
                *v = new_id;
                self.guard.tokenstates.remove(&act_id);
                self.guard.tokenstates.insert(new_id, new_tokenstate);
                return new_id;
            }
        }
        panic!()
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct AccountId {
    // The account ID may change frequently, and if it wraps, we lose correctness, so we use a
    // ludicrously large type. On my current desktop machine a quick measurement suggests that if
    // this was incremented at the maximum possible continuous rate, it would take about
    // 4,522,155,402,651,803,058,176 years before this wrapped. In contrast if we were to,
    // recklessly, use a u64 it could wrap in a blink-and-you-miss-it 245 years.
    id: u128,
}

impl AccountId {
    fn new(guard: &mut LockedState) -> Self {
        let new_id = Self {
            id: guard.account_count,
        };
        guard.account_count += 1;
        new_id
    }
}

#[derive(Clone, Debug)]
pub enum TokenState {
    /// Authentication is neither pending nor active.
    Empty,
    /// Pending authentication
    Pending {
        code_verifier: String,
        last_notification: Option<Instant>,
        state: String,
        url: Url,
    },
    /// There is an active token (and, possibly, also an active refresh token).
    Active {
        access_token: String,
        refreshed_at: Instant,
        /// The instant in time when the last ongoing, or unsuccessful, refresh attempt was made.
        last_refresh_attempt: Option<Instant>,
        /// The instant in time when the user was last warned that refreshing had not yet
        /// succeeded.
        last_refresh_warning: Option<Instant>,
        expiry: Instant,
        refresh_token: Option<String>,
    },
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::server::refresher::Refresher;

    #[test]
    fn test_act_validation() {
        let conf1_str = r#"
            account "x" {
                auth_uri = "http://a.com";
                client_id = "b";
                client_secret = "c";
                scopes = ["d", "e"];
                redirect_uri = "http://f.com";
                token_uri = "http://g.com";
            }
            "#;
        let conf2_str = r#"
            account "x" {
                auth_uri = "http://h.com";
                client_id = "b";
                client_secret = "c";
                scopes = ["d", "e"];
                redirect_uri = "http://f.com";
                token_uri = "http://g.com";
            }
            "#;
        let conf3_str = r#"
            account "x" {
                auth_uri = "http://a.com";
                client_id = "b";
                client_secret = "c";
                scopes = ["d", "e"];
                redirect_uri = "http://f.com";
                token_uri = "http://g.com";
            }

            account "y" {
                auth_uri = "http://a.com";
                client_id = "b";
                client_secret = "c";
                scopes = ["d", "e"];
                redirect_uri = "http://f.com";
                token_uri = "http://g.com";
            }
            "#;

        let conf = Config::from_str(conf1_str).unwrap();
        let notifier = Arc::new(Notifier::new().unwrap());
        let pstate = AuthenticatorState::new(PathBuf::new(), conf, 0, notifier, Refresher::new());
        let mut old_x_id;
        {
            let ct_lk = pstate.ct_lock();
            let act_id = ct_lk.validate_act_name("x").unwrap();
            old_x_id = act_id;
            assert_eq!(act_id, AccountId { id: 0 });
            assert!(matches!(ct_lk.tokenstate(act_id), TokenState::Empty));
        }

        let conf = Config::from_str(conf2_str).unwrap();
        pstate.update_conf(conf);
        {
            let ct_lk = pstate.ct_lock();
            let act_id = ct_lk.validate_act_name("x").unwrap();
            assert_ne!(act_id, old_x_id);
            old_x_id = act_id;
            assert!(matches!(ct_lk.tokenstate(act_id), TokenState::Empty));
        }

        let conf = Config::from_str(conf2_str).unwrap();
        pstate.update_conf(conf);
        {
            let ct_lk = pstate.ct_lock();
            let act_id = ct_lk.validate_act_name("x").unwrap();
            assert_eq!(act_id, old_x_id);
            assert!(matches!(ct_lk.tokenstate(act_id), TokenState::Empty));
        }

        let conf = Config::from_str(conf3_str).unwrap();
        pstate.update_conf(conf);
        let old_y_ver;
        {
            let ct_lk = pstate.ct_lock();
            let act_id = ct_lk.validate_act_name("x").unwrap();
            assert_ne!(act_id, old_x_id);
            old_x_id = act_id;
            assert!(matches!(ct_lk.tokenstate(act_id), TokenState::Empty));

            let act_id = ct_lk.validate_act_name("y").unwrap();
            old_y_ver = act_id.id;
            assert!(matches!(ct_lk.tokenstate(act_id), TokenState::Empty));
        }

        let conf = Config::from_str(conf2_str).unwrap();
        pstate.update_conf(conf);
        {
            let ct_lk = pstate.ct_lock();

            let act_id = ct_lk.validate_act_name("x").unwrap();
            assert_ne!(act_id, old_x_id);
            old_x_id = act_id;
            assert!(matches!(ct_lk.tokenstate(act_id), TokenState::Empty));

            assert!(ct_lk.validate_act_name("y").is_none());
            assert!(!ct_lk.is_act_id_valid(AccountId { id: old_y_ver }));
        }

        {
            let mut ct_lk = pstate.ct_lock();
            let act_id = ct_lk.validate_act_name("x").unwrap();
            let act_id = ct_lk.tokenstate_replace(
                act_id,
                TokenState::Pending {
                    code_verifier: "abc".to_owned(),
                    last_notification: None,
                    state: "xyz".to_string(),
                    url: Url::parse("http://a.com/").unwrap(),
                },
            );
            assert_ne!(act_id, old_x_id);
            old_x_id = act_id;
            assert!(matches!(
                ct_lk.tokenstate(act_id),
                TokenState::Pending { .. }
            ));
        }

        let conf = Config::from_str(conf2_str).unwrap();
        pstate.update_conf(conf);
        {
            let ct_lk = pstate.ct_lock();
            let act_id = ct_lk.validate_act_name("x").unwrap();
            assert_eq!(act_id, old_x_id);
            assert!(matches!(
                ct_lk.tokenstate(act_id),
                TokenState::Pending { .. }
            ));
        }

        let conf = Config::from_str(conf1_str).unwrap();
        pstate.update_conf(conf);
        {
            let ct_lk = pstate.ct_lock();
            let act_id = ct_lk.validate_act_name("x").unwrap();
            assert_ne!(act_id, old_x_id);
            assert!(matches!(ct_lk.tokenstate(act_id), TokenState::Empty));
        }
    }
}
