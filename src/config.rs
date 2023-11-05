use std::{
    collections::HashMap, error::Error, fs::read_to_string, path::Path, sync::Arc, time::Duration,
};

use lrlex::{lrlex_mod, DefaultLexerTypes, LRNonStreamingLexer};
use lrpar::{lrpar_mod, NonStreamingLexer, Span};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::config_ast;

lrlex_mod!("config.l");
lrpar_mod!("config.y");

type StorageT = u8;

/// How many seconds before an access token's expiry do we try refreshing it?
const REFRESH_BEFORE_EXPIRY_DEFAULT: Duration = Duration::from_secs(90);
/// How many seconds before we forcibly try refreshing an access token, even if it's not yet
/// expired?
const REFRESH_AT_LEAST_DEFAULT: Duration = Duration::from_secs(90 * 60);
/// How many seconds after a refresh failed in a non-permanent way before we retry refreshing?
const REFRESH_RETRY_DEFAULT: Duration = Duration::from_secs(40);
/// How many seconds do we raise a notification if it only contains authorisations that have been
/// shown before?
const AUTH_NOTIFY_INTERVAL_DEFAULT: u64 = 15 * 60;
/// What is the default bind() address for the HTTP server?
const HTTP_LISTEN_DEFAULT: &str = "127.0.0.1:0";

#[derive(Debug)]
pub struct Config {
    pub accounts: HashMap<String, Arc<Account>>,
    pub auth_notify_cmd: Option<String>,
    pub auth_notify_interval: Duration,
    pub error_notify_cmd: Option<String>,
    pub http_listen: String,
    pub transient_error_if_cmd: Option<String>,
    refresh_at_least: Option<Duration>,
    refresh_before_expiry: Option<Duration>,
    refresh_retry: Option<Duration>,
    pub token_event_cmd: Option<String>,
}

impl Config {
    /// Create a `Config` from `path`, returning `Err(String)` (containing a human readable
    /// message) if it was unable to do so.
    pub fn from_path(conf_path: &Path) -> Result<Self, String> {
        let input = match read_to_string(conf_path) {
            Ok(s) => s,
            Err(e) => return Err(format!("Can't read {:?}: {}", conf_path, e)),
        };
        Config::from_str(&input)
    }

    pub fn from_str(input: &str) -> Result<Self, String> {
        let lexerdef = config_l::lexerdef();
        let lexer = lexerdef.lexer(input);
        let (astopt, errs) = config_y::parse(&lexer);
        if !errs.is_empty() {
            let msgs = errs
                .iter()
                .map(|e| e.pp(&lexer, &config_y::token_epp))
                .collect::<Vec<_>>();
            return Err(msgs.join("\n"));
        }

        let mut accounts = HashMap::new();
        let mut auth_notify_cmd = None;
        let mut auth_notify_interval = None;
        let mut error_notify_cmd = None;
        let mut http_listen = None;
        let mut transient_error_if_cmd = None;
        let mut refresh_at_least = None;
        let mut refresh_before_expiry = None;
        let mut refresh_retry = None;
        let mut token_event_cmd = None;
        match astopt {
            Some(Ok(opts)) => {
                for opt in opts {
                    match opt {
                        config_ast::TopLevel::Account(overall_span, name, fields) => {
                            let act_name = unescape_str(lexer.span_str(name));
                            accounts.insert(
                                act_name.clone(),
                                Arc::new(Account::from_fields(
                                    act_name,
                                    &lexer,
                                    overall_span,
                                    fields,
                                )?),
                            );
                        }
                        config_ast::TopLevel::AuthErrorCmd(span) => {
                            return Err(error_at_span(
                                &lexer,
                                span,
                                "'auth_error_cmd' has been renamed to 'error_notify_cmd'",
                            ));
                        }
                        config_ast::TopLevel::AuthNotifyCmd(span) => {
                            auth_notify_cmd = Some(check_not_assigned_str(
                                &lexer,
                                "auth_notify_cmd",
                                span,
                                auth_notify_cmd,
                            )?)
                        }
                        config_ast::TopLevel::AuthNotifyInterval(span) => {
                            auth_notify_interval =
                                Some(time_str_to_duration(check_not_assigned_time(
                                    &lexer,
                                    "auth_notify_interval",
                                    span,
                                    auth_notify_interval,
                                )?)?)
                        }
                        config_ast::TopLevel::ErrorNotifyCmd(span) => {
                            error_notify_cmd = Some(check_not_assigned_str(
                                &lexer,
                                "error_notify_cmd",
                                span,
                                error_notify_cmd,
                            )?)
                        }
                        config_ast::TopLevel::HttpListen(span) => {
                            http_listen = Some(check_not_assigned_str(
                                &lexer,
                                "http_listen",
                                span,
                                http_listen,
                            )?)
                        }
                        config_ast::TopLevel::TransientErrorIfCmd(span) => {
                            transient_error_if_cmd = Some(check_not_assigned_str(
                                &lexer,
                                "transient_error_if_cmd",
                                span,
                                transient_error_if_cmd,
                            )?)
                        }
                        config_ast::TopLevel::RefreshAtLeast(span) => {
                            refresh_at_least = Some(time_str_to_duration(check_not_assigned_time(
                                &lexer,
                                "refresh_at_least",
                                span,
                                refresh_at_least,
                            )?)?)
                        }
                        config_ast::TopLevel::RefreshBeforeExpiry(span) => {
                            refresh_before_expiry =
                                Some(time_str_to_duration(check_not_assigned_time(
                                    &lexer,
                                    "refresh_before_expiry",
                                    span,
                                    refresh_before_expiry,
                                )?)?)
                        }
                        config_ast::TopLevel::RefreshRetry(span) => {
                            refresh_retry = Some(time_str_to_duration(check_not_assigned_time(
                                &lexer,
                                "refresh_retry",
                                span,
                                refresh_retry,
                            )?)?)
                        }
                        config_ast::TopLevel::TokenEventCmd(span) => {
                            token_event_cmd = Some(check_not_assigned_str(
                                &lexer,
                                "token_event_cmd",
                                span,
                                token_event_cmd,
                            )?)
                        }
                    }
                }
            }
            _ => unreachable!(),
        }

        if accounts.is_empty() {
            return Err("Must specify at least one account".into());
        }

        Ok(Config {
            accounts,
            auth_notify_cmd,
            auth_notify_interval: auth_notify_interval
                .unwrap_or_else(|| Duration::from_secs(AUTH_NOTIFY_INTERVAL_DEFAULT)),
            error_notify_cmd,
            http_listen: http_listen.unwrap_or_else(|| HTTP_LISTEN_DEFAULT.to_owned()),
            transient_error_if_cmd,
            refresh_at_least,
            refresh_before_expiry,
            refresh_retry,
            token_event_cmd,
        })
    }
}

fn check_not_assigned_str<T>(
    lexer: &LRNonStreamingLexer<DefaultLexerTypes<StorageT>>,
    name: &str,
    span: Span,
    v: Option<T>,
) -> Result<String, String> {
    match v {
        None => Ok(unescape_str(lexer.span_str(span))),
        Some(_) => Err(error_at_span(
            lexer,
            span,
            &format!("Mustn't specify '{name:}' more than once"),
        )),
    }
}

fn check_not_assigned_time<'a, T>(
    lexer: &'a LRNonStreamingLexer<DefaultLexerTypes<StorageT>>,
    name: &str,
    span: Span,
    v: Option<T>,
) -> Result<&'a str, String> {
    match v {
        None => Ok(lexer.span_str(span)),
        Some(_) => Err(error_at_span(
            lexer,
            span,
            &format!("Mustn't specify '{name:}' more than once"),
        )),
    }
}

fn check_not_assigned_uri<T>(
    lexer: &LRNonStreamingLexer<DefaultLexerTypes<StorageT>>,
    name: &str,
    span: Span,
    v: Option<T>,
) -> Result<String, String> {
    match v {
        None => {
            let s = unescape_str(lexer.span_str(span));
            match Url::parse(&s) {
                Ok(_) => Ok(s),
                Err(e) => Err(error_at_span(lexer, span, &format!("Invalid URI: {e:}"))),
            }
        }
        Some(_) => Err(error_at_span(
            lexer,
            span,
            &format!("Mustn't specify '{name:}' more than once"),
        )),
    }
}

fn check_assigned<T>(
    lexer: &LRNonStreamingLexer<DefaultLexerTypes<StorageT>>,
    name: &str,
    span: Span,
    v: Option<T>,
) -> Result<T, String> {
    match v {
        Some(x) => Ok(x),
        None => Err(error_at_span(
            lexer,
            span,
            &format!("{name:} not specified"),
        )),
    }
}

/// If you add to the, or alter the semantics of any existing, fields in this struct, you *must*
/// check whether any of the following also need to be chnaged:
///   * `Account::secure_eq`
///   * `Account::dump`
///   * `Account::secure_restoreable`
///   * `AccountDump`
/// These functions are vital to the security guarantees pizauth makes when reloading/restoring
/// configurations.
#[derive(Clone, Debug)]
pub struct Account {
    pub name: String,
    pub auth_uri: String,
    pub auth_uri_fields: Vec<(String, String)>,
    pub client_id: String,
    pub client_secret: Option<String>,
    redirect_uri: String,
    refresh_at_least: Option<Duration>,
    refresh_before_expiry: Option<Duration>,
    refresh_retry: Option<Duration>,
    pub scopes: Vec<String>,
    pub token_uri: String,
}

impl Account {
    fn from_fields(
        name: String,
        lexer: &LRNonStreamingLexer<DefaultLexerTypes<StorageT>>,
        overall_span: Span,
        fields: Vec<config_ast::AccountField>,
    ) -> Result<Self, String> {
        let mut auth_uri = None;
        let mut auth_uri_fields = None;
        let mut client_id = None;
        let mut client_secret = None;
        let mut login_hint = None;
        let mut redirect_uri = None;
        let mut refresh_at_least = None;
        let mut refresh_before_expiry = None;
        let mut refresh_retry = None;
        let mut scopes = None;
        let mut token_uri = None;

        for f in fields {
            match f {
                config_ast::AccountField::AuthUri(span) => {
                    auth_uri = Some(check_not_assigned_uri(lexer, "auth_uri", span, auth_uri)?)
                }
                config_ast::AccountField::AuthUriFields(span, spans) => {
                    if auth_uri_fields.is_some() {
                        debug_assert!(!spans.is_empty());
                        return Err(error_at_span(
                            lexer,
                            span,
                            "Mustn't specify 'auth_uri_fields' more than once",
                        ));
                    }
                    auth_uri_fields = Some(
                        spans
                            .iter()
                            .map(|(key_sp, val_sp)| {
                                (
                                    unescape_str(lexer.span_str(*key_sp)),
                                    unescape_str(lexer.span_str(*val_sp)),
                                )
                            })
                            .collect::<Vec<(String, String)>>(),
                    );
                }
                config_ast::AccountField::ClientId(span) => {
                    client_id = Some(check_not_assigned_str(lexer, "client_id", span, client_id)?)
                }
                config_ast::AccountField::ClientSecret(span) => {
                    client_secret = Some(check_not_assigned_str(
                        lexer,
                        "client_secret",
                        span,
                        client_secret,
                    )?)
                }
                config_ast::AccountField::LoginHint(span) => {
                    login_hint = Some(check_not_assigned_str(
                        lexer,
                        "login_hint",
                        span,
                        login_hint,
                    )?)
                }
                config_ast::AccountField::RedirectUri(span) => {
                    redirect_uri = Some(check_not_assigned_uri(
                        lexer,
                        "redirect_uri",
                        span,
                        redirect_uri,
                    )?)
                }
                config_ast::AccountField::RefreshAtLeast(span) => {
                    refresh_at_least = Some(time_str_to_duration(check_not_assigned_time(
                        lexer,
                        "refresh_at_least",
                        span,
                        refresh_at_least,
                    )?)?)
                }
                config_ast::AccountField::RefreshBeforeExpiry(span) => {
                    refresh_before_expiry = Some(time_str_to_duration(check_not_assigned_time(
                        lexer,
                        "refresh_before_expiry",
                        span,
                        refresh_before_expiry,
                    )?)?)
                }
                config_ast::AccountField::RefreshRetry(span) => {
                    refresh_retry = Some(time_str_to_duration(check_not_assigned_time(
                        lexer,
                        "refresh_retry",
                        span,
                        refresh_retry,
                    )?)?)
                }
                config_ast::AccountField::Scopes(span, spans) => {
                    if scopes.is_some() {
                        debug_assert!(!spans.is_empty());
                        return Err(error_at_span(
                            lexer,
                            span,
                            "Mustn't specify 'scopes' more than once",
                        ));
                    }
                    scopes = Some(
                        spans
                            .iter()
                            .map(|sp| unescape_str(lexer.span_str(*sp)))
                            .collect::<Vec<String>>(),
                    );
                }
                config_ast::AccountField::TokenUri(span) => {
                    token_uri = Some(check_not_assigned_uri(lexer, "token_uri", span, token_uri)?)
                }
            }
        }

        let auth_uri = check_assigned(lexer, "auth_uri", overall_span, auth_uri)?;
        let client_id = check_assigned(lexer, "client_id", overall_span, client_id)?;
        let token_uri = check_assigned(lexer, "token_uri", overall_span, token_uri)?;

        // We allow the deprecated `login_hint` field through but don't want to allow it to clash
        // with a field of the same name in `auth_uri_fields`.
        if let (Some(_), Some(auth_uri_fields)) = (&login_hint, &auth_uri_fields) {
            if auth_uri_fields.iter().any(|(k, _)| k == "login_hint") {
                return Err(error_at_span(lexer, overall_span, "Both the 'login_hint' attribute and a 'auth_uri_fields' field with the name 'login_hint' are specified. The 'login_hint' attribute is deprecated so remove it."));
            }
        }

        Ok(Account {
            name,
            auth_uri,
            auth_uri_fields: auth_uri_fields.unwrap_or_default(),
            client_id,
            client_secret,
            redirect_uri: redirect_uri.unwrap_or_else(|| "http://localhost/".to_owned()),
            refresh_at_least,
            refresh_before_expiry,
            refresh_retry,
            scopes: scopes.unwrap_or_default(),
            token_uri,
        })
    }

    /// Are the security relevant parts of this `Account` the same as `other`?
    ///
    /// Note that this is a weaker condition than "is `self` equal to `other`" because there are
    /// some parts of an `Account`'s configuration that are irrelevant from a security perspective.
    /// If you add new fields to, or change the semantics of existing fields in, `Account`, you
    /// must reconsider this function.
    pub fn secure_eq(&self, other: &Self) -> bool {
        // Our definition of "are the security relevant parts of this `Account` the same as
        // `other`" is roughly: if anything here changes could we end up giving out an access token
        // that the user might send to the wrong server? Note that it is better to be safe than
        // sorry: if in doubt, it is better to have more, rather than fewer, fields compared here.
        self.name == other.name
            && self.auth_uri == other.auth_uri
            && self.auth_uri_fields == other.auth_uri_fields
            && self.client_id == other.client_id
            && self.client_secret == other.client_secret
            && self.redirect_uri == other.redirect_uri
            && self.scopes == other.scopes
            && self.token_uri == other.token_uri
    }

    pub fn dump(&self) -> AccountDump {
        AccountDump {
            auth_uri: self.auth_uri.clone(),
            auth_uri_fields: self.auth_uri_fields.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            redirect_uri: self.redirect_uri.clone(),
            scopes: self.scopes.clone(),
            token_uri: self.token_uri.clone(),
        }
    }

    /// Can this account's tokenstate safely be restored from an [AccountDump] `act_dump`? Roughly
    /// speaking, if `act_dump` was converted into an `Account`, would that new `Account` compare
    /// equal with `secure_eq` to `self`? If `true`, then it is safe to restore the (`self`)
    /// `Account`'s tokenstate from a dump.
    pub fn secure_restorable(&self, act_dump: &AccountDump) -> bool {
        self.auth_uri == act_dump.auth_uri
            && self.auth_uri_fields == act_dump.auth_uri_fields
            && self.client_id == act_dump.client_id
            && self.client_secret == act_dump.client_secret
            && self.redirect_uri == act_dump.redirect_uri
            && self.scopes == act_dump.scopes
            && self.token_uri == act_dump.token_uri
    }

    pub fn redirect_uri(&self, http_port: u16) -> Result<Url, Box<dyn Error>> {
        let mut url = Url::parse(&self.redirect_uri)?;
        url.set_port(Some(http_port))
            .map_err(|_| "Cannot set port")?;
        Ok(url)
    }

    pub fn refresh_at_least(&self, config: &Config) -> Duration {
        self.refresh_at_least
            .or(config.refresh_at_least)
            .unwrap_or(REFRESH_AT_LEAST_DEFAULT)
    }

    pub fn refresh_before_expiry(&self, config: &Config) -> Duration {
        self.refresh_before_expiry
            .or(config.refresh_before_expiry)
            .unwrap_or(REFRESH_BEFORE_EXPIRY_DEFAULT)
    }

    pub fn refresh_retry(&self, config: &Config) -> Duration {
        self.refresh_retry
            .or(config.refresh_retry)
            .unwrap_or(REFRESH_RETRY_DEFAULT)
    }
}

#[derive(Deserialize, Serialize)]
pub struct AccountDump {
    auth_uri: String,
    auth_uri_fields: Vec<(String, String)>,
    client_id: String,
    client_secret: Option<String>,
    redirect_uri: String,
    scopes: Vec<String>,
    token_uri: String,
}

/// Given a time duration in the format `[0-9]+[dhms]` return a [Duration].
///
/// # Panics
///
/// If `t` is not in the format `[0-9]+[dhms]`.
fn time_str_to_duration(t: &str) -> Result<Duration, String> {
    fn inner(t: &str) -> Result<Duration, Box<dyn Error>> {
        let last_char_idx = t
            .chars()
            .filter(|c| c.is_numeric())
            .map(|c| c.len_utf8())
            .sum();
        debug_assert!(last_char_idx < t.len());
        let num = t[..last_char_idx].parse::<u64>()?;
        let secs = match t.chars().last().unwrap() {
            'd' => num.checked_mul(86400).ok_or("Number too big")?,
            'h' => num.checked_mul(3600).ok_or("Number too big")?,
            'm' => num.checked_mul(60).ok_or("Number too big")?,
            's' => num,
            _ => unreachable!(),
        };
        Ok(Duration::from_secs(secs))
    }
    inner(t).map_err(|e| format!("Invalid time: {e}"))
}

/// Take a quoted string from the config file and unescape it (i.e. strip the start and end quote
/// (") characters and process any escape characters in the string.)
fn unescape_str(us: &str) -> String {
    // The regex in config.l should have guaranteed that strings start and finish with a
    // quote character.
    debug_assert!(us.starts_with('"') && us.ends_with('"'));
    let mut s = String::new();
    // We iterate over all characters except the opening and closing quote characters.
    let mut i = '"'.len_utf8();
    while i < us.len() - '"'.len_utf8() {
        let c = us[i..].chars().next().unwrap();
        if c == '\\' {
            // The regex in config.l should have guaranteed that there are no unescaped quote (")
            // characters, but we check here just to be sure.
            debug_assert!(i < us.len() - '"'.len_utf8());
            i += 1;
            let c2 = us[i..].chars().next().unwrap();
            debug_assert!(c2 == '"' || c2 == '\\');
            s.push(c2);
            i += c2.len_utf8();
        } else {
            s.push(c);
            i += c.len_utf8();
        }
    }
    s
}

/// Return an error message pinpointing `span` as the culprit.
fn error_at_span(
    lexer: &LRNonStreamingLexer<DefaultLexerTypes<StorageT>>,
    span: Span,
    msg: &str,
) -> String {
    let ((line_off, col), _) = lexer.line_col(span);
    let code = lexer
        .span_lines_str(span)
        .split('\n')
        .next()
        .unwrap()
        .trim();
    format!(
        "Line {}, column {}:\n  {}\n{}",
        line_off,
        col,
        code.trim(),
        msg
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use lrpar::Lexer;

    #[test]
    fn test_unescape_string() {
        assert_eq!(unescape_str("\"\""), "");
        assert_eq!(unescape_str("\"a\""), "a");
        assert_eq!(unescape_str("\"a\\\"\""), "a\"");
        assert_eq!(unescape_str("\"a\\\"b\""), "a\"b");
        assert_eq!(unescape_str("\"\\\\\""), "\\");
    }

    #[test]
    fn test_time_str_to_duration() {
        assert_eq!(time_str_to_duration("0s").unwrap(), Duration::from_secs(0));
        assert_eq!(time_str_to_duration("1s").unwrap(), Duration::from_secs(1));
        assert_eq!(time_str_to_duration("1m").unwrap(), Duration::from_secs(60));
        assert_eq!(
            time_str_to_duration("2m").unwrap(),
            Duration::from_secs(120)
        );
        assert_eq!(
            time_str_to_duration("1h").unwrap(),
            Duration::from_secs(3600)
        );
        assert_eq!(
            time_str_to_duration("1d").unwrap(),
            Duration::from_secs(86400)
        );

        assert!(time_str_to_duration("9223372036854775808m").is_err());
    }

    #[test]
    fn string_escapes() {
        let lexerdef = config_l::lexerdef();
        let lexemes = lexerdef.lexer("\"\\\\\"").iter().collect::<Vec<_>>();
        assert_eq!(lexemes.len(), 1);
        let lexemes = lexerdef.lexer("\"\\\"\\\"\"").iter().collect::<Vec<_>>();
        assert_eq!(lexemes.len(), 1);
        let lexemes = lexerdef.lexer("\"\\n\"").iter().collect::<Vec<_>>();
        assert_eq!(lexemes.len(), 4);
    }

    #[test]
    fn valid_config() {
        let c = Config::from_str(
            r#"
            auth_notify_cmd = "g";
            auth_notify_interval = 88m;
            error_notify_cmd = "j";
            http_listen = "127.0.0.1:56789";
            transient_error_if_cmd = "k";
            token_event_cmd = "q";
            account "x" {
                // Mandatory fields
                auth_uri = "http://a.com";
                auth_uri_fields = {"l": "m", "n": "o", "l": "p"};
                client_id = "b";
                scopes = ["c", "d"];
                token_uri = "http://f.com";
                // Optional fields
                client_secret = "h";
                login_hint = "i";
                redirect_uri = "http://e.com";
                refresh_at_least = 43m;
                refresh_before_expiry = 42s;
                refresh_retry = 33s;
            }
        "#,
        )
        .unwrap();
        assert_eq!(c.error_notify_cmd, Some("j".to_owned()));
        assert_eq!(c.auth_notify_cmd, Some("g".to_owned()));
        assert_eq!(c.auth_notify_interval, Duration::from_secs(88 * 60));
        assert_eq!(c.http_listen, "127.0.0.1:56789".to_owned());
        assert_eq!(c.transient_error_if_cmd, Some("k".to_owned()));
        assert_eq!(c.token_event_cmd, Some("q".to_owned()));

        let act = &c.accounts["x"];
        assert_eq!(act.auth_uri, "http://a.com");
        assert_eq!(
            &act.auth_uri_fields,
            &[
                ("l".to_owned(), "m".to_owned()),
                ("n".to_owned(), "o".to_owned()),
                ("l".to_owned(), "p".to_owned())
            ]
        );
        assert_eq!(act.client_id, "b");
        assert_eq!(act.client_secret, Some("h".to_owned()));
        assert_eq!(act.redirect_uri, "http://e.com");
        assert_eq!(act.token_uri, "http://f.com");
        assert_eq!(&act.scopes, &["c".to_owned(), "d".to_owned()]);
        assert_eq!(act.refresh_at_least, Some(Duration::from_secs(43 * 60)));
        assert_eq!(act.refresh_before_expiry, Some(Duration::from_secs(42)));
        assert_eq!(act.refresh_retry(&c), Duration::from_secs(33));
    }

    #[test]
    fn at_least_one_account() {
        assert_eq!(
            Config::from_str("").unwrap_err().as_str(),
            "Must specify at least one account"
        );
    }

    #[test]
    fn invalid_time() {
        match Config::from_str("auth_notify_interval = 18446744073709551616s;") {
            Err(s) if s.contains("Invalid time: number too large") => (),
            _ => panic!(),
        }
    }

    #[test]
    fn dup_fields() {
        match Config::from_str(r#"auth_notify_cmd = "a"; auth_notify_cmd = "a";"#) {
            Err(s) if s.contains("Mustn't specify 'auth_notify_cmd' more than once") => (),
            _ => panic!(),
        }
        match Config::from_str("auth_notify_interval = 1s; auth_notify_interval = 2s;") {
            Err(s) if s.contains("Mustn't specify 'auth_notify_interval' more than once") => (),
            _ => panic!(),
        }
        match Config::from_str(r#"error_notify_cmd = "a"; error_notify_cmd = "a";"#) {
            Err(s) if s.contains("Mustn't specify 'error_notify_cmd' more than once") => (),
            _ => panic!(),
        }
        match Config::from_str(r#"token_event_cmd = "a"; token_event_cmd = "a";"#) {
            Err(s) if s.contains("Mustn't specify 'token_event_cmd' more than once") => (),
            _ => panic!(),
        }
        match Config::from_str(r#"transient_error_if_cmd = "a"; transient_error_if_cmd = "b";"#) {
            Err(s) if s.contains("Mustn't specify 'transient_error_if_cmd' more than once") => (),
            _ => panic!(),
        }
        match Config::from_str(r#"http_listen = "a"; http_listen = "b";"#) {
            Err(s) if s.contains("Mustn't specify 'http_listen' more than once") => (),
            _ => panic!(),
        }

        fn account_dup(field: &str, values: &[&str]) {
            let c = format!(
                "account \"x\" {{ {} }}",
                values
                    .iter()
                    .map(|v| format!("{field:} = {v:};"))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            match Config::from_str(&c) {
                Err(s) if s.contains(&format!("Mustn't specify '{field:}' more than once")) => (),
                Err(e) => panic!("{e:}"),
                _ => panic!(),
            }
        }

        account_dup("auth_uri", &[r#""http://a.com/""#, r#""http://b.com/""#]);
        account_dup("auth_uri_fields", &[r#"{"a": "b"}"#, r#"{"c": "d"}"#]);
        account_dup("client_id", &[r#""a""#, r#""b""#]);
        account_dup("client_secret", &[r#""a""#, r#""b""#]);
        account_dup("login_hint", &[r#""a""#, r#""b""#]);
        account_dup(
            "redirect_uri",
            &[r#""http://a.com/""#, r#""http://b.com/""#],
        );
        account_dup("refresh_before_expiry", &["1m", "2m"]);
        account_dup("refresh_at_least", &["1m", "2m"]);
        account_dup("scopes", &[r#"["a"]"#, r#"["b"]"#]);
        account_dup("token_uri", &[r#""http://a.com/""#, r#""http://b.com/""#]);
    }

    #[test]
    fn invalid_uris() {
        fn invalid_uri(field: &str) {
            let c = format!(r#"account "x" {{ {field} = "blah"; }}"#);
            match Config::from_str(&c) {
                Err(e) if e.contains("Invalid URI") => (),
                Err(e) => panic!("{e:}"),
                _ => panic!(),
            }
        }

        invalid_uri("auth_uri");
        invalid_uri("redirect_uri");
        invalid_uri("token_uri");
    }

    #[test]
    fn mandatory_account_fields() {
        let fields = &[
            ("auth_uri", r#""http://a.com/""#),
            ("client_id", r#""a""#),
            ("token_uri", r#""http://b.com/""#),
        ];

        fn combine(fields: &[(&str, &str)]) -> String {
            fields
                .iter()
                .map(|(k, v)| format!("{k:} = {v:};"))
                .collect::<Vec<_>>()
                .join("\n")
        }

        assert!(Config::from_str(&format!(r#"account "a" {{ {} }}"#, combine(fields))).is_ok());
        for i in 0..fields.len() {
            let mut f = fields.to_vec();
            f.remove(i);
            match Config::from_str(&format!(r#"account "a" {{ {} }}"#, combine(&f))) {
                Err(e) if e.contains("not specified") => (),
                Err(e) => panic!("{e:}"),
                e => panic!("{e:?}"),
            }
        }
    }

    #[test]
    fn local_overrides() {
        // Defaults only
        let c = Config::from_str(
            r#"
            account "x" {
                auth_uri = "http://a.com";
                client_id = "b";
                scopes = ["c"];
                token_uri = "http://d.com";
            }
        "#,
        )
        .unwrap();
        assert_eq!(c.transient_error_if_cmd, None);
        assert_eq!(c.refresh_at_least, None);
        assert_eq!(c.refresh_before_expiry, None);
        assert_eq!(c.refresh_retry, None);

        let act = &c.accounts["x"];
        assert_eq!(act.refresh_at_least(&c), REFRESH_AT_LEAST_DEFAULT);
        assert_eq!(act.refresh_before_expiry(&c), REFRESH_BEFORE_EXPIRY_DEFAULT);
        assert_eq!(act.refresh_retry(&c), REFRESH_RETRY_DEFAULT);

        // Global only
        let c = Config::from_str(
            r#"
            transient_error_if_cmd = "e";
            refresh_at_least = 1s;
            refresh_before_expiry = 2s;
            refresh_retry = 3s;
            account "x" {
                auth_uri = "http://a.com";
                client_id = "b";
                scopes = ["c"];
                token_uri = "http://d.com";
            }
        "#,
        )
        .unwrap();
        assert_eq!(c.transient_error_if_cmd, Some("e".to_owned()));
        assert_eq!(c.refresh_at_least, Some(Duration::from_secs(1)));
        assert_eq!(c.refresh_before_expiry, Some(Duration::from_secs(2)));
        assert_eq!(c.refresh_retry, Some(Duration::from_secs(3)));

        let act = &c.accounts["x"];
        assert_eq!(act.refresh_at_least(&c), Duration::from_secs(1));
        assert_eq!(act.refresh_before_expiry(&c), Duration::from_secs(2));
        assert_eq!(act.refresh_retry(&c), Duration::from_secs(3));

        // Local only
        let c = Config::from_str(
            r#"
            account "x" {
                auth_uri = "http://a.com";
                client_id = "b";
                scopes = ["c"];
                token_uri = "http://d.com";
                refresh_at_least = 1s;
                refresh_before_expiry = 2s;
                refresh_retry = 3s;
            }
        "#,
        )
        .unwrap();

        assert_eq!(c.transient_error_if_cmd, None);
        assert_eq!(c.refresh_at_least, None);
        assert_eq!(c.refresh_before_expiry, None);
        assert_eq!(c.refresh_retry, None);

        let act = &c.accounts["x"];
        assert_eq!(act.refresh_at_least(&c), Duration::from_secs(1));
        assert_eq!(act.refresh_before_expiry(&c), Duration::from_secs(2));
        assert_eq!(act.refresh_retry(&c), Duration::from_secs(3));

        // Local overrides global
        let c = Config::from_str(
            r#"
            transient_error_if_cmd = "e";
            refresh_at_least = 1s;
            refresh_before_expiry = 2s;
            refresh_retry = 3s;
            account "x" {
                auth_uri = "http://a.com";
                client_id = "b";
                scopes = ["c"];
                token_uri = "http://d.com";
                refresh_at_least = 4s;
                refresh_before_expiry = 5s;
                refresh_retry = 6s;
            }
        "#,
        )
        .unwrap();
        assert_eq!(c.transient_error_if_cmd, Some("e".to_owned()));
        assert_eq!(c.refresh_at_least, Some(Duration::from_secs(1)));
        assert_eq!(c.refresh_before_expiry, Some(Duration::from_secs(2)));
        assert_eq!(c.refresh_retry, Some(Duration::from_secs(3)));

        let act = &c.accounts["x"];
        assert_eq!(act.refresh_at_least(&c), Duration::from_secs(4));
        assert_eq!(act.refresh_before_expiry(&c), Duration::from_secs(5));
        assert_eq!(act.refresh_retry(&c), Duration::from_secs(6));

        // Local overrides global
        let c = Config::from_str(
            r#"
            transient_error_if_cmd = "e";
            refresh_at_least = 1s;
            refresh_before_expiry = 2s;
            refresh_retry = 3s;
            account "x" {
                auth_uri = "http://a.com";
                client_id = "b";
                scopes = ["c"];
                token_uri = "http://d.com";
                refresh_at_least = 4s;
                refresh_before_expiry = 5s;
                refresh_retry = 6s;
            }
            account "y" {
                auth_uri = "http://g.com";
                client_id = "h";
                scopes = ["i"];
                token_uri = "http://j.com";
                refresh_at_least = 7s;
                refresh_before_expiry = 8s;
                refresh_retry = 9s;
            }
            account "z" {
                auth_uri = "http://g.com";
                client_id = "h";
                scopes = ["i"];
                token_uri = "http://j.com";
            }
        "#,
        )
        .unwrap();
        assert_eq!(c.transient_error_if_cmd, Some("e".to_owned()));
        assert_eq!(c.refresh_at_least, Some(Duration::from_secs(1)));
        assert_eq!(c.refresh_before_expiry, Some(Duration::from_secs(2)));
        assert_eq!(c.refresh_retry, Some(Duration::from_secs(3)));

        let act = &c.accounts["x"];
        assert_eq!(act.refresh_at_least(&c), Duration::from_secs(4));
        assert_eq!(act.refresh_before_expiry(&c), Duration::from_secs(5));
        assert_eq!(act.refresh_retry(&c), Duration::from_secs(6));

        let act = &c.accounts["y"];
        assert_eq!(act.refresh_at_least(&c), Duration::from_secs(7));
        assert_eq!(act.refresh_before_expiry(&c), Duration::from_secs(8));
        assert_eq!(act.refresh_retry(&c), Duration::from_secs(9));

        let act = &c.accounts["z"];
        assert_eq!(act.refresh_at_least(&c), Duration::from_secs(1));
        assert_eq!(act.refresh_before_expiry(&c), Duration::from_secs(2));
        assert_eq!(act.refresh_retry(&c), Duration::from_secs(3));
    }

    #[test]
    fn login_hint_mutually_exclusive_query_field() {
        let c = format!(
            r#"account "x" {{
            auth_uri = "http://a.com/";
            auth_uri_fields = {{ "login_hint": "e" }};
            client_id = "b";
            token_uri = "https://c.com/";
            login_hint = "d";
          }}"#
        );
        match Config::from_str(&c) {
            Err(e) if e.contains("Both the 'login_hint' attribute and a 'auth_uri_fields' field with the name 'login_hint' are specified. The 'login_hint' attribute is deprecated so remove it.") => (),
            Err(e) => panic!("{e:}"),
            _ => panic!(),
        }
    }
}
