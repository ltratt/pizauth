//! This module contains pizauth's core central state. [AuthenticatorState] is the global state,
//! but mostly what one is interested in are [Account]s and [TokenState]s. These are (literally)
//! locked together: every [Account] has a [TokenState] and vice versa. However, a challenge is
//! that we allow users to reload their config at any point: we have to be very careful about
//! associating an [Account] with a [TokenState], as we don't want to hand out credentials for an
//! old version of an account.
//!
//! To that end, we provide an abstraction [AccountId] which is a sort-of "the current version of
//! an [Account]". Any change to the user's configuration of an [Account] *or* a change to an
//! [Account]'s associated [TokenState] will cause the [AccountId] to change. Every time a
//! [CTGuard] is dropped/reacquired, or [tokenstate_replace] is called, [AccountId]s must be
//! revalidated. Failing to do so will cause panics.

use std::{
    collections::HashMap,
    error::Error,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::SystemTime,
};

use boot_time::Instant;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{rng, Rng};
use serde::{Deserialize, Serialize};
use url::Url;

use super::{eventer::Eventer, notifier::Notifier, refresher::Refresher};
use crate::config::{Account, AccountDump, Config};

/// We lightly encrypt the dump output to make it at least resistant to simple string-based
/// grepping. This is the length of the dump nonce.
const NONCE_LEN: usize = 12;
/// The ChaCha20 key for the dump.
const CHACHA20_KEY: &[u8; 32] = b"\x66\xa2\x47\xa8\x5e\x48\xcf\xec\xaa\xed\x9b\x36\xeb\xa9\x7d\x53\x50\xd4\x28\x63\x75\x09\x7a\x44\xee\xff\xb9\xc4\x54\x6b\x65\xa3";
/// The format of the dump. Monotonically increment if the semantics of the `pizauth dump` change
/// in an incompatible manner.
const DUMP_VERSION: u64 = 1;

/// pizauth's global state.
pub struct AuthenticatorState {
    pub conf_path: PathBuf,
    /// The "global lock" protecting the config and current [TokenState]s. Can only be accessed via
    /// [AuthenticatorState::ct_lock].
    locked_state: Mutex<LockedState>,
    /// Port of the HTTP server required by OAuth.
    pub http_port: Option<u16>,
    /// Port of the HTTPS server required by OAuth.
    pub https_port: Option<u16>,
    /// If an HTTPS server is running, its raw public key formatted in hex with each byte separated by `:`.
    pub https_pub_key: Option<String>,
    pub eventer: Arc<Eventer>,
    pub notifier: Arc<Notifier>,
    pub refresher: Arc<Refresher>,
}

impl AuthenticatorState {
    pub fn new(
        conf_path: PathBuf,
        conf: Config,
        http_port: Option<u16>,
        https_port: Option<u16>,
        https_pub_key: Option<String>,
        eventer: Arc<Eventer>,
        notifier: Arc<Notifier>,
        refresher: Arc<Refresher>,
    ) -> Self {
        AuthenticatorState {
            conf_path,
            locked_state: Mutex::new(LockedState::new(conf)),
            http_port,
            https_port,
            https_pub_key,
            eventer,
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
    pub fn ct_lock(&self) -> CTGuard<'_> {
        CTGuard::new(self.locked_state.lock().unwrap())
    }

    /// Update the global [Config] to `new_conf`. This cannot fail, but note that there is no
    /// guarantee that by the time this function calls the configuration is still the same as
    /// `new_conf` since another thread(s) may also have called this function.
    pub fn update_conf(&self, new_conf: Config) {
        {
            let mut lk = self.locked_state.lock().unwrap();
            lk.update_conf(new_conf);
        }
        self.notifier.notify_changes();
        self.refresher.notify_changes();
    }

    pub fn dump(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let lk = self.locked_state.lock().unwrap();
        let d = lk.dump()?;
        drop(lk);

        // The aim of encrypting the dump output isn't to render it impossible to decrypt, but to
        // at least make it harder for people to shoot themselves in the foot by leaving important
        // information lurking on a file system in a way that `grep` or `strings` can easily find.
        let key = Key::from_slice(CHACHA20_KEY);
        let cipher = ChaCha20Poly1305::new(key);
        let mut nonce = [0u8; NONCE_LEN];
        rng().fill(&mut nonce[..]);
        let nonce = Nonce::from_slice(&nonce);
        let bytes = cipher
            .encrypt(nonce, &*d)
            .map_err(|_| "Creating dump failed.")?;
        let mut buf = Vec::from(nonce.as_slice());
        buf.extend(&bytes);
        Ok(buf)
    }

    pub fn restore(&self, d: Vec<u8>) -> Result<(), Box<dyn Error>> {
        if d.len() < NONCE_LEN {
            return Err("Input too short")?;
        }
        let key = Key::from_slice(CHACHA20_KEY);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = &d[..NONCE_LEN];
        let encrypted = &d[NONCE_LEN..];
        let d = cipher
            .decrypt(Nonce::from_slice(nonce), encrypted.as_ref())
            .map_err(|_| "Restoring dump failed")?;

        let lk = self.locked_state.lock().unwrap().restore(d);
        drop(lk);
        self.notifier.notify_changes();
        self.refresher.notify_changes();
        Ok(())
    }
}

/// An invariant "I1" that must be maintained at all times is that the set of keys in
/// `LockedState.config.Config.accounts` must exactly equal `LockedState.tokenstates`. This
/// invariant is relied upon by a number of `unwrap` calls which assume that if a key `x` was found
/// in one of these sets it is guaranteed to be found in the other.
struct LockedState {
    config: Config,
    details: Vec<(String, AccountId, TokenState)>,
    /// The next [AccountId] we'll hand out.
    ///
    // The account ID may change frequently, and if it wraps, we lose correctness, so we use a
    // ludicrously large type. On my current desktop machine a quick measurement suggests that if
    // this was incremented at the maximum possible continuous rate, it would take about
    // 4,522,155,402,651,803,058,176 years before this wrapped. In contrast if we were to,
    // recklessly, use a u64 it could wrap in a blink-and-you-miss-it 245 years.
    next_account_id: u128,
}

impl LockedState {
    fn new(config: Config) -> Self {
        let mut details = Vec::with_capacity(config.accounts.len());

        let mut next_account_id = 0;
        for act_name in config.accounts.keys() {
            let act_id = AccountId {
                id: next_account_id,
            };
            next_account_id += 1;
            details.push((act_name.to_owned(), act_id, TokenState::Empty));
        }

        LockedState {
            next_account_id,
            config,
            details,
        }
    }

    fn update_conf(&mut self, config: Config) {
        let mut details = Vec::with_capacity(config.accounts.len());

        for act_name in config.accounts.keys() {
            if let Some(old_act) = self.config.accounts.get(act_name) {
                let new_act = &config.accounts[act_name];
                if new_act.secure_eq(old_act) {
                    // We know that `self.details` must contain `act_name` so the unwrap is safe.
                    details.push(
                        self.details
                            .iter()
                            .find(|x| x.0 == act_name.as_str())
                            .unwrap()
                            .clone(),
                    );
                } else {
                    // The two accounts are not the same so we can't reuse the existing tokenstate,
                    // instead keeping it as Empty. However, we need to increment the version
                    // number, because there could be a very long-running thread that started
                    // acting on an Empty tokenstate, did something (very slowly), and now wants to
                    // update its status, even though multiple other updates have happened in the
                    // interim. Incrementing the version implicitly invalidates whatever (slow...)
                    // calculation it has performed.
                    details.push((
                        act_name.to_owned(),
                        self.next_account_id(),
                        TokenState::Empty,
                    ));
                }
            } else {
                details.push((
                    act_name.to_owned(),
                    self.next_account_id(),
                    TokenState::Empty,
                ));
            }
        }

        self.config = config;
        self.details = details;
    }

    fn dump(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut acts = HashMap::with_capacity(self.details.len());
        for (act_name, _, ts) in &self.details {
            acts.insert(
                act_name.to_owned(),
                (self.config.accounts[act_name.as_str()].dump(), ts.dump()),
            );
        }

        Ok(bincode::serde::encode_to_vec(
            &Dump {
                version: DUMP_VERSION,
                accounts: acts,
            },
            bincode::config::legacy(),
        )?)
    }

    fn restore(&mut self, dump: Vec<u8>) -> Result<(), Box<dyn Error>> {
        let d: Dump = bincode::serde::decode_from_slice(&dump, bincode::config::legacy())?.0;
        if d.version != DUMP_VERSION {
            return Err("Unknown dump version".into());
        }

        let mut restore = HashMap::new();
        for (act_name, _, old_ts) in &self.details {
            let act = &self.config.accounts[act_name.as_str()];
            if let Some((act_dump, ts_dump)) = d.accounts.get(act_name) {
                if act.secure_restorable(act_dump) {
                    let new_ts = TokenState::restore(ts_dump);
                    match (old_ts, &new_ts) {
                        (
                            &TokenState::Empty | &TokenState::Pending { .. },
                            &TokenState::Empty | &TokenState::Pending { .. },
                        ) => (),
                        (
                            &TokenState::Empty | &TokenState::Pending { .. },
                            &TokenState::Active { .. },
                        ) => {
                            restore.insert(act_name.to_owned(), new_ts);
                        }
                        (&TokenState::Active { .. }, _) => (),
                    }
                }
            }
        }

        for (act_name, ts) in restore.drain() {
            let ts_idx = self
                .details
                .iter()
                .position(|(n, _, _)| n == &act_name)
                .unwrap();
            self.details[ts_idx].1 = self.next_account_id();
            self.details[ts_idx].2 = ts;
        }

        Ok(())
    }

    /// Returns a unique [AccountId].
    fn next_account_id(&mut self) -> AccountId {
        let new_id = AccountId {
            id: self.next_account_id,
        };
        self.next_account_id += 1;
        new_id
    }
}

#[derive(Deserialize, Serialize)]
struct Dump {
    version: u64,
    accounts: HashMap<String, (AccountDump, TokenStateDump)>,
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
    fn new(guard: MutexGuard<'a, LockedState>) -> CTGuard<'a> {
        CTGuard { guard }
    }

    pub fn config(&self) -> &Config {
        &self.guard.config
    }

    /// If `act_name` references a current account, return a [AccountId].
    pub fn validate_act_name(&self, act_name: &str) -> Option<AccountId> {
        self.guard
            .details
            .iter()
            .find(|x| x.0 == act_name)
            .map(|x| x.1)
    }

    /// Is `act_id` still a valid [AccountId]?
    pub fn is_act_id_valid(&self, act_id: AccountId) -> bool {
        self.guard.details.iter().any(|x| x.1 == act_id)
    }

    /// An iterator that will produce one [AccountId] for each currently active account.
    pub fn act_ids(&self) -> impl Iterator<Item = AccountId> + '_ {
        self.guard.details.iter().map(|x| x.1)
    }

    /// Return the [AccountId] with state `state`.
    pub fn act_id_matching_token_state(&self, state: &str) -> Option<AccountId> {
        self.guard
            .details
            .iter()
            .find(|x| matches!(&x.2, TokenState::Pending { state: s, .. } if s == state))
            .map(|x| x.1)
    }

    /// Return the [Account] for account `act_id`.
    ///
    /// # Panics
    ///
    /// If `act_id` is not valid.
    pub fn account(&self, act_id: AccountId) -> &Account {
        let act_name = self
            .guard
            .details
            .iter()
            .find(|x| x.1 == act_id)
            .map(|x| &x.0)
            .unwrap();
        &self.guard.config.accounts[act_name]
    }

    /// Return a reference to the [TokenState] of `act_id`. The user must have validated `act_id`
    /// under the current [CTGuard].
    ///
    /// # Panics
    ///
    /// If `act_id` is not valid.
    pub fn tokenstate(&self, act_id: AccountId) -> &TokenState {
        self.guard
            .details
            .iter()
            .find(|x| x.1 == act_id)
            .map(|x| &x.2)
            .unwrap()
    }

    /// If `act_id` is `Active`, set `ongoing_refresh` to `new_ongoing_refresh` and return the new
    /// `AccountId`.
    ///
    /// # Panics
    ///
    /// If `act_id` is not valid or is not `Active`.
    pub fn tokenstate_set_ongoing_refresh(
        &mut self,
        act_id: AccountId,
        new_ongoing_refresh: bool,
    ) -> AccountId {
        let i = self
            .guard
            .details
            .iter()
            .position(|x| x.1 == act_id)
            .unwrap();

        let new_id = self.guard.next_account_id();
        let ts = &mut self.guard.details[i];
        if let TokenState::Active {
            ref mut ongoing_refresh,
            ..
        } = ts.2
        {
            ts.1 = new_id;
            *ongoing_refresh = new_ongoing_refresh;
            return new_id;
        }
        unreachable!();
    }

    /// Update the tokenstate for `act_id` to `new_tokenstate` returning a new [AccountId]
    /// valid for the new tokenstate, updating the tokenstate version.
    ///
    /// # Panics
    ///
    /// If `act_id` is not valid.
    pub fn tokenstate_replace(
        &mut self,
        act_id: AccountId,
        new_tokenstate: TokenState,
    ) -> AccountId {
        let i = self
            .guard
            .details
            .iter()
            .position(|x| x.1 == act_id)
            .unwrap();
        let new_id = self.guard.next_account_id();
        self.guard.details[i].1 = new_id;
        self.guard.details[i].2 = new_tokenstate;
        new_id
    }
}

/// An account ID. Must be created by [LockedState::next_account_id].
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct AccountId {
    id: u128,
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
        /// When did we obtain the current access_token?
        access_token_obtained: Instant,
        /// When does the current access token expire?
        access_token_expiry: Instant,
        /// We may have been given a refresh token which may allow us to obtain another access
        /// token when the existing one expires (notice the two "may"s!). The remaining fields in
        /// the `Active` variant are only relevant if `refresh_token` is `Some(...)`.
        refresh_token: Option<String>,
        /// Is the refresher currently trying to refresh this token?
        ongoing_refresh: bool,
        /// How many times in a row has refreshing failed? This will be reset to zero when
        /// refreshing succeeds.
        consecutive_refresh_fails: u64,
        /// The instant in time when the last ongoing, or unsuccessful, refresh attempt was made.
        last_refresh_attempt: Option<Instant>,
    },
}

#[derive(Deserialize, Serialize)]
/// The format of a dumped [TokenState]. Note that [std::time::Instant] instances are translated to
/// [std::time::SystemTime] instances: there is no guarantee that we can precisely represent the
/// latter as the former, so when conversions fail we default to setting values to
/// [std::time::Instant::now()] or [std::time::SystemTime::now()], as appropriate, as a safe
/// fallback.
pub enum TokenStateDump {
    Empty,
    Active {
        access_token: String,
        access_token_obtained: SystemTime,
        access_token_expiry: SystemTime,
        refresh_token: Option<String>,
    },
}

impl TokenState {
    pub fn dump(&self) -> TokenStateDump {
        fn dump_instant(i: &Instant) -> SystemTime {
            let t;
            if let Some(d) = i.checked_duration_since(Instant::now()) {
                // Instant is in the future
                t = SystemTime::now().checked_add(d);
            } else if let Some(d) = Instant::now().checked_duration_since(*i) {
                // Instant is in the past
                t = SystemTime::now().checked_sub(d);
            } else {
                t = None;
            }
            t.unwrap_or_else(SystemTime::now)
        }

        match self {
            TokenState::Empty => TokenStateDump::Empty,
            TokenState::Pending { .. } => TokenStateDump::Empty,
            TokenState::Active {
                access_token,
                access_token_obtained,
                access_token_expiry,
                refresh_token,
                ongoing_refresh: _,
                consecutive_refresh_fails: _,
                last_refresh_attempt: _,
            } => TokenStateDump::Active {
                access_token: access_token.to_owned(),
                access_token_obtained: dump_instant(access_token_obtained),
                access_token_expiry: dump_instant(access_token_expiry),
                refresh_token: refresh_token.clone(),
            },
        }
    }

    pub fn restore(tsd: &TokenStateDump) -> TokenState {
        fn restore_instant(t: &SystemTime) -> Instant {
            let i;
            if let Ok(d) = t.duration_since(SystemTime::now()) {
                // SystemTime is in the future
                i = Instant::now().checked_add(d);
            } else if let Ok(d) = SystemTime::now().duration_since(*t) {
                // SystemTime is in the past
                i = Instant::now().checked_sub(d);
            } else {
                i = None;
            }
            i.unwrap_or_else(Instant::now)
        }

        match tsd {
            TokenStateDump::Empty => TokenState::Empty,
            TokenStateDump::Active {
                access_token,
                access_token_obtained,
                access_token_expiry,
                refresh_token,
            } => TokenState::Active {
                access_token: access_token.clone(),
                access_token_obtained: restore_instant(access_token_obtained),
                access_token_expiry: restore_instant(access_token_expiry),
                refresh_token: refresh_token.clone(),
                ongoing_refresh: false,
                consecutive_refresh_fails: 0,
                last_refresh_attempt: None,
            },
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::server::refresher::Refresher;
    use std::time::Duration;

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
        let eventer = Arc::new(Eventer::new().unwrap());
        let notifier = Arc::new(Notifier::new().unwrap());
        let pstate = AuthenticatorState::new(
            PathBuf::new(),
            conf,
            Some(0),
            Some(0),
            Some("".to_string()),
            eventer,
            notifier,
            Refresher::new(),
        );
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

    #[test]
    fn dump_restore() {
        let conf_str = r#"
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

        let conf = Config::from_str(conf_str).unwrap();
        let eventer = Arc::new(Eventer::new().unwrap());
        let notifier = Arc::new(Notifier::new().unwrap());
        let pstate = AuthenticatorState::new(
            PathBuf::new(),
            conf,
            Some(0),
            Some(0),
            Some("".to_string()),
            eventer,
            notifier,
            Refresher::new(),
        );
        let old_x_id;
        {
            let ct_lk = pstate.ct_lock();
            old_x_id = ct_lk.validate_act_name("x").unwrap();
            assert!(matches!(ct_lk.tokenstate(old_x_id), TokenState::Empty));
        }
        let dump = pstate.dump().unwrap();

        {
            pstate.restore(dump.clone()).unwrap();

            let ct_lk = pstate.ct_lock();
            let x_id = ct_lk.validate_act_name("x").unwrap();
            assert_eq!(old_x_id, x_id);
            assert!(matches!(ct_lk.tokenstate(x_id), TokenState::Empty));
        }

        {
            let mut ct_lk = pstate.ct_lock();
            let act_id = ct_lk.validate_act_name("x").unwrap();
            ct_lk.tokenstate_replace(
                act_id,
                TokenState::Pending {
                    code_verifier: "abc".to_owned(),
                    last_notification: None,
                    state: "xyz".to_string(),
                    url: Url::parse("http://a.com/").unwrap(),
                },
            );
        }

        {
            pstate.restore(dump.clone()).unwrap();

            let ct_lk = pstate.ct_lock();
            let x_id = ct_lk.validate_act_name("x").unwrap();
            assert_ne!(old_x_id, x_id);
            assert!(matches!(ct_lk.tokenstate(x_id), TokenState::Pending { .. }));
        }

        {
            let mut ct_lk = pstate.ct_lock();
            let act_id = ct_lk.validate_act_name("x").unwrap();
            ct_lk.tokenstate_replace(
                act_id,
                TokenState::Active {
                    access_token: "abc".to_owned(),
                    access_token_obtained: Instant::now(),
                    access_token_expiry: Instant::now()
                        .checked_add(Duration::from_secs(60))
                        .unwrap(),
                    refresh_token: None,
                    ongoing_refresh: false,
                    consecutive_refresh_fails: 0,
                    last_refresh_attempt: None,
                },
            );
        }
        let dump = pstate.dump().unwrap();

        {
            pstate.restore(dump.clone()).unwrap();

            let ct_lk = pstate.ct_lock();
            let x_id = ct_lk.validate_act_name("x").unwrap();
            assert_ne!(old_x_id, x_id);
            assert!(matches!(ct_lk.tokenstate(x_id), TokenState::Active { .. }));
        }

        let conf = Config::from_str(conf_str).unwrap();
        let eventer = Arc::new(Eventer::new().unwrap());
        let notifier = Arc::new(Notifier::new().unwrap());
        let pstate = AuthenticatorState::new(
            PathBuf::new(),
            conf,
            Some(0),
            Some(0),
            Some("".to_string()),
            eventer,
            notifier,
            Refresher::new(),
        );

        let old_x_id;
        {
            let ct_lk = pstate.ct_lock();
            old_x_id = ct_lk.validate_act_name("x").unwrap();
            assert!(matches!(ct_lk.tokenstate(old_x_id), TokenState::Empty));
        }

        {
            pstate.restore(dump.clone()).unwrap();

            let ct_lk = pstate.ct_lock();
            let x_id = ct_lk.validate_act_name("x").unwrap();
            dbg!(ct_lk.tokenstate(x_id));
            assert_ne!(old_x_id, x_id);
            assert!(matches!(ct_lk.tokenstate(x_id), TokenState::Active { .. }));
        }
    }
}
