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

#[cfg(debug_assertions)]
use std::collections::HashSet;
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
    conf_tokens: Mutex<(Config, HashMap<String, TokenStateVersion>)>,
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
            .map(|(k, _)| {
                (
                    k.to_owned(),
                    TokenStateVersion {
                        version: 0,
                        tokenstate: TokenState::Empty,
                    },
                )
            })
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

    /// Update the global [Config] to `new_conf`. This cannot fail, but note that there is no
    /// guarantee that by the time this function calls the configuration is still the same as
    /// `new_conf` since another thread(s) may also have called this function.
    pub fn update_conf(&self, new_conf: Config) {
        let mut lk = self.conf_tokens.lock().unwrap();
        // Remove all `TokenState`s that no longer correspond to an account (i.e. GC
        // `TokenState`s).
        for k in lk.1.keys().cloned().collect::<Vec<_>>() {
            if !new_conf.accounts.contains_key(&k) {
                lk.1.remove(&k);
            }
        }
        // Set the `TokenState` of any changed, or new, accounts to `Empty`.
        for (act_name, new_act) in new_conf.accounts.iter() {
            match lk.0.accounts.get(act_name) {
                Some(old_act) => {
                    // If the account has changed in any way, reset the TokenStateVersion.
                    if new_act != old_act {
                        // It might seem like we could keep the version unchanged, or even reset it
                        // to zero, but there could be a very long-running thread that started acting
                        // on an Empty tokenstate, did something (very slowly), and now wants to
                        // update its status, even though multiple other updates have happened in
                        // the interim. Incrementing the version implicitly invalidates whatever
                        // (slow...) calculation it has performed.
                        //
                        // See invariant "I1" in [CTGuard] for the `unwrap` safety guarantee.
                        let version = lk.1.get(&new_act.name).unwrap().version + 1;
                        lk.1.insert(
                            act_name.to_owned(),
                            TokenStateVersion {
                                version,
                                tokenstate: TokenState::Empty,
                            },
                        );
                    }
                }
                None => {
                    lk.1.insert(
                        act_name.to_owned(),
                        TokenStateVersion {
                            version: 0,
                            tokenstate: TokenState::Empty,
                        },
                    );
                }
            }
        }
        lk.0 = new_conf;

        debug_assert_eq!(
            HashSet::<&String>::from_iter(lk.0.accounts.keys()),
            HashSet::from_iter(lk.1.keys()),
        );
    }
}

/// A lock guard around the [Config] and tokens. When this guard is dropped:
///
///   1. the config lock will be released.
///   2. any [CTGuardAccountId] instances created from this [CTGuard] will no longer by valid
///      i.e. they will not be able to access [Account]s or [TokenState]s until they are
///      revalidated.
pub struct CTGuard<'a> {
    // An invariant "I1" that must be maintained at all times is that the set of keys in
    // `guard.0.Config.accounts` must exactly equal `guard.1`. This invariant is relied upon by a
    // number of `unwrap` calls which assume that if a key `x` was found in one of these sets it is
    // guaranteed to be found in the other.
    guard: MutexGuard<'a, (Config, HashMap<String, TokenStateVersion>)>,
    act_rc: Rc<()>,
}

impl<'a> CTGuard<'a> {
    fn new(guard: MutexGuard<'a, (Config, HashMap<String, TokenStateVersion>)>) -> CTGuard {
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
        match self.guard.0.accounts.get(act_name) {
            Some(act) => {
                // See invariant "I1" in [CTGuard] for the `unwrap` safety guarantee.
                let tokenstate_version = self.guard.1.get(act_name).unwrap().version;
                Some(CTGuardAccountId {
                    account: Arc::clone(act),
                    tokenstate_version,
                    guard_rc: Rc::downgrade(&self.act_rc),
                })
            }
            None => None,
        }
    }

    /// If `act_id` would still be a valid account under the current [CTGuard], create a new
    /// [CTGuardAccountId] which can be used in its stead. If the input `act_id` is no longer
    /// valid, return `None`.
    pub fn validate_act_id(&self, act_id: CTGuardAccountId) -> Option<CTGuardAccountId> {
        match self.guard.0.accounts.get(&act_id.account.name) {
            // We use `Arc::ptr_eq` because it's strictly stronger than `==`: it's possible for an
            // account X to be changed from having contents C to C' and back to C, and we don't
            // want to assume those two `C`s are equivalent.
            Some(act) if Arc::ptr_eq(&act_id.account, act) => {
                // See invariant "I1" in [CTGuard] for the `unwrap` safety guarantee.
                let tokenstate_version = self.guard.1.get(&act_id.account.name).unwrap().version;
                if act_id.tokenstate_version == tokenstate_version {
                    Some(CTGuardAccountId {
                        account: act_id.account,
                        tokenstate_version,
                        guard_rc: Rc::downgrade(&self.act_rc),
                    })
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// An iterator that will produce one [CTGuardAccountId] for each currently active account.
    pub fn act_ids(&self) -> impl Iterator<Item = CTGuardAccountId> + '_ {
        self.guard.0.accounts.values().map(|act| {
            let tokenstate_version = self.guard.1.get(&act.name).unwrap().version;
            CTGuardAccountId {
                account: Arc::clone(act),
                tokenstate_version,
                guard_rc: Rc::downgrade(&self.act_rc),
            }
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
        &self.guard.1.get(&act_id.account.name).unwrap().tokenstate
    }

    /// Update the tokenstate for `act_id` to `new_tokenstate` returning a new [CTGuardAccountId]
    /// valid for the new tokenstate.
    ///
    /// # Panics
    ///
    /// If `act_id` has outlived its parent [CTGuard].
    pub fn tokenstate_replace(
        &mut self,
        mut act_id: CTGuardAccountId,
        new_tokenstate: TokenState,
    ) -> CTGuardAccountId {
        if Weak::strong_count(&act_id.guard_rc) != 1 {
            panic!("CTGuardAccountId has outlived its parent CTGuard.");
        }
        let mut ts_ver = self.guard.1.get_mut(&act_id.account.name).unwrap();
        debug_assert_eq!(ts_ver.version, act_id.tokenstate_version);
        ts_ver.version += 1;
        ts_ver.tokenstate = new_tokenstate;
        act_id.tokenstate_version = ts_ver.version;
        act_id
    }

    /// If the current tokenstate is [TokenState::Pending], update the last notification time to
    /// `notification.
    ///
    /// # Panics
    ///
    /// If the tokenstate for `act_id` is not [TokenState::Pending].
    pub fn tokenstate_update_last_notification(
        &mut self,
        act_id: &CTGuardAccountId,
        notification: Option<Instant>,
    ) {
        if Weak::strong_count(&act_id.guard_rc) != 1 {
            panic!("CTGuardAccountId has outlived its parent CTGuard.");
        }
        match self
            .guard
            .1
            .get_mut(&act_id.account.name)
            .unwrap()
            .tokenstate
        {
            TokenState::Pending {
                ref mut last_notification,
                ..
            } => *last_notification = notification,
            _ => unreachable!(),
        }
    }
}

/// An opaque account identifier, only fully valid while the [CTGuard] it was created from is not
/// dropped. While the [CTGuardAccountId] is valid, it can be used to lookup [Account]s and
/// [TokenState]s without further validity checks. After the [CTGuard] it was created from is
/// dropped, one cannot use a `CTGuardAccountId` to query token states (etc.), but can use it to
/// compare whether an old and a new `CTGuardAccountId` reference the same underlying [Account].
pub struct CTGuardAccountId {
    account: Arc<Account>,
    // The tokenstate version may change frequently, and if it wraps, we lose correctness, so we
    // that if this was incremented at the maximum possible continuous rate, it would take about
    // 4,522,155,402,651,803,058,176 years before this wrapped. In contrast if we were to,
    // recklessly, use a u64 it could wrap in a blink-and-you-miss-it 245 years.
    tokenstate_version: u128,
    guard_rc: Weak<()>,
}

/// Track the version of a [TokenState].
struct TokenStateVersion {
    version: u128,
    tokenstate: TokenState,
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::server::refresher::refresher_setup;

    struct DummyFrontend;

    impl Frontend for DummyFrontend {
        fn new() -> Result<Self, Box<dyn std::error::Error>>
        where
            Self: Sized,
        {
            todo!()
        }

        fn main_loop(&self) -> Result<(), Box<dyn std::error::Error>> {
            todo!()
        }

        fn notify_error(&self, _msg: &str) -> Result<(), Box<dyn std::error::Error>> {
            todo!()
        }

        fn notify_success(&self, _msg: &str) -> Result<(), Box<dyn std::error::Error>> {
            todo!()
        }

        fn notify_authorisations(
            &self,
            _to_notify: Vec<(String, Url)>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            todo!()
        }
    }

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
        let frontend = Arc::<Box<dyn Frontend>>::new(Box::new(DummyFrontend));
        let notifier = Arc::new(Notifier::new().unwrap());
        let pstate =
            AuthenticatorState::new(conf, 0, frontend, notifier, refresher_setup().unwrap());

        {
            let ct_lk = pstate.ct_lock();
            let act_id = ct_lk.validate_act_name("x").unwrap();
            assert!(matches!(ct_lk.tokenstate(&act_id), TokenState::Empty));
            assert!(matches!(
                ct_lk.guard.1.get("x").unwrap(),
                TokenStateVersion {
                    tokenstate: TokenState::Empty,
                    version: 0
                }
            ));
        }

        let conf = Config::from_str(conf2_str).unwrap();
        pstate.update_conf(conf);
        {
            let ct_lk = pstate.ct_lock();
            assert!(matches!(
                ct_lk.guard.1.get("x").unwrap(),
                TokenStateVersion {
                    tokenstate: TokenState::Empty,
                    version: 1
                }
            ));
        }

        let conf = Config::from_str(conf2_str).unwrap();
        pstate.update_conf(conf);
        {
            let ct_lk = pstate.ct_lock();
            assert!(matches!(
                ct_lk.guard.1.get("x").unwrap(),
                TokenStateVersion {
                    tokenstate: TokenState::Empty,
                    version: 1
                }
            ));
        }

        let conf = Config::from_str(conf3_str).unwrap();
        pstate.update_conf(conf);
        {
            let ct_lk = pstate.ct_lock();
            assert!(matches!(
                ct_lk.guard.1.get("x").unwrap(),
                TokenStateVersion {
                    tokenstate: TokenState::Empty,
                    version: 2
                }
            ));
            assert!(ct_lk.validate_act_name("x").is_some());
            assert!(ct_lk.validate_act_name("y").is_some());
            assert!(matches!(
                ct_lk.guard.1.get("y").unwrap(),
                TokenStateVersion {
                    tokenstate: TokenState::Empty,
                    version: 0
                }
            ));
        }

        let conf = Config::from_str(conf2_str).unwrap();
        pstate.update_conf(conf);
        {
            let ct_lk = pstate.ct_lock();
            assert!(matches!(
                ct_lk.guard.1.get("x").unwrap(),
                TokenStateVersion {
                    tokenstate: TokenState::Empty,
                    version: 3
                }
            ));
            assert!(ct_lk.validate_act_name("x").is_some());
            assert!(ct_lk.validate_act_name("y").is_none());
        }

        {
            let mut ct_lk = pstate.ct_lock();
            let act_id = ct_lk.validate_act_name("x").unwrap();
            let act_id = ct_lk.validate_act_id(act_id).unwrap();
            let act_id = ct_lk.tokenstate_replace(
                act_id,
                TokenState::Pending {
                    last_notification: None,
                    state: [0, 1, 2, 3, 4, 5, 6, 7],
                    url: Url::parse("http://a.com/").unwrap(),
                },
            );
            assert!(matches!(
                ct_lk.guard.1.get("x").unwrap(),
                TokenStateVersion {
                    tokenstate: TokenState::Pending { .. },
                    version: 4
                }
            ));
            assert!(ct_lk.validate_act_id(act_id).is_some());
        }

        let conf = Config::from_str(conf2_str).unwrap();
        pstate.update_conf(conf);
        {
            let ct_lk = pstate.ct_lock();
            assert!(matches!(
                ct_lk.guard.1.get("x").unwrap(),
                TokenStateVersion {
                    tokenstate: TokenState::Pending { .. },
                    version: 4
                }
            ));
        }

        let conf = Config::from_str(conf1_str).unwrap();
        pstate.update_conf(conf);
        {
            let ct_lk = pstate.ct_lock();
            assert!(matches!(
                ct_lk.guard.1.get("x").unwrap(),
                TokenStateVersion {
                    tokenstate: TokenState::Empty,
                    version: 5
                }
            ));
        }
    }
}
