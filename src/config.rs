use std::{
    collections::HashMap, error::Error, fs::read_to_string, path::Path, sync::Arc, time::Duration,
};

use lrlex::{lrlex_mod, DefaultLexeme, LRNonStreamingLexer};
use lrpar::{lrpar_mod, NonStreamingLexer, Span};
use url::Url;

use crate::config_ast;

lrlex_mod!("config.l");
lrpar_mod!("config.y");

type StorageT = u8;

/// How many seconds before an access token's expiry do we try refreshing it?
const REFRESH_BEFORE_EXPIRY_DEFAULT: u64 = 90;
/// How many seconds before we forcibly try refreshing an access token, even if it's not yet
/// expired?
const REFRESH_AT_LEAST_DEFAULT: u64 = 90 * 60;
/// How many seconds do we raise a notification if it only contains authorisations that have been
/// shown before?
const NOTIFY_INTERVAL_DEFAULT: u64 = 15 * 60;
/// How many seconds after a refresh failed in a non-permanent way before we retry refreshing?
const REFRESH_RETRY_INTERVAL_DEFAULT: u64 = 40;

#[derive(Debug, PartialEq)]
pub struct Config {
    pub accounts: HashMap<String, Arc<Account>>,
    pub notify_interval: Duration,
    pub refresh_retry_interval: Duration,
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
        let mut notify_interval = None;
        let mut refresh_retry_interval = None;
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
                        config_ast::TopLevel::NotifyInterval(span) => {
                            match time_str_to_duration(check_not_assigned_time(
                                &lexer,
                                "notify_interval",
                                span,
                                notify_interval,
                            )?) {
                                Ok(t) => notify_interval = Some(t),
                                Err(e) => {
                                    return Err(error_at_span(
                                        &lexer,
                                        span,
                                        &format!("Invalid time: {e:}"),
                                    ))
                                }
                            }
                        }
                        config_ast::TopLevel::RefreshRetryInterval(span) => {
                            match time_str_to_duration(check_not_assigned_time(
                                &lexer,
                                "refresh_retry_interval",
                                span,
                                refresh_retry_interval,
                            )?) {
                                Ok(t) => refresh_retry_interval = Some(t),
                                Err(e) => {
                                    return Err(error_at_span(
                                        &lexer,
                                        span,
                                        &format!("Invalid time: {e:}"),
                                    ))
                                }
                            }
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
            notify_interval: notify_interval
                .unwrap_or_else(|| Duration::from_secs(NOTIFY_INTERVAL_DEFAULT)),
            refresh_retry_interval: refresh_retry_interval
                .unwrap_or_else(|| Duration::from_secs(REFRESH_RETRY_INTERVAL_DEFAULT)),
        })
    }
}

fn check_not_assigned_str<T>(
    lexer: &LRNonStreamingLexer<DefaultLexeme<StorageT>, StorageT>,
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
    lexer: &'a LRNonStreamingLexer<DefaultLexeme<StorageT>, StorageT>,
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
    lexer: &LRNonStreamingLexer<DefaultLexeme<StorageT>, StorageT>,
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
    lexer: &LRNonStreamingLexer<DefaultLexeme<StorageT>, StorageT>,
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

#[derive(Debug, PartialEq)]
pub struct Account {
    pub auth_cmd: Option<String>,
    pub name: String,
    pub auth_uri: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub login_hint: Option<String>,
    redirect_uri: String,
    pub refresh_before_expiry: Option<Duration>,
    pub refresh_at_least: Option<Duration>,
    pub scopes: Vec<String>,
    pub token_uri: String,
}

impl Account {
    fn from_fields(
        name: String,
        lexer: &LRNonStreamingLexer<DefaultLexeme<StorageT>, StorageT>,
        overall_span: Span,
        fields: Vec<config_ast::AccountField>,
    ) -> Result<Self, String> {
        let mut auth_cmd = None;
        let mut auth_uri = None;
        let mut client_id = None;
        let mut client_secret = None;
        let mut login_hint = None;
        let mut redirect_uri = None;
        let mut refresh_before_expiry = None;
        let mut refresh_at_least = None;
        let mut scopes = None;
        let mut token_uri = None;

        for f in fields {
            match f {
                config_ast::AccountField::AuthCmd(span) => {
                    auth_cmd = Some(check_not_assigned_str(lexer, "auth_cmd", span, auth_cmd)?)
                }
                config_ast::AccountField::AuthUri(span) => {
                    auth_uri = Some(check_not_assigned_uri(lexer, "auth_uri", span, auth_uri)?)
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
                config_ast::AccountField::RefreshBeforeExpiry(span) => {
                    match time_str_to_duration(check_not_assigned_time(
                        lexer,
                        "refresh_before_expiry",
                        span,
                        refresh_before_expiry,
                    )?) {
                        Ok(t) => refresh_before_expiry = Some(t),
                        Err(e) => {
                            return Err(error_at_span(lexer, span, &format!("Invalid time: {e:}")))
                        }
                    }
                }
                config_ast::AccountField::RefreshAtLeast(span) => {
                    match time_str_to_duration(check_not_assigned_time(
                        lexer,
                        "refresh_at_least",
                        span,
                        refresh_at_least,
                    )?) {
                        Ok(t) => refresh_at_least = Some(t),
                        Err(e) => {
                            return Err(error_at_span(lexer, span, &format!("Invalid time: {e:}")))
                        }
                    }
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
                    if spans.is_empty() {
                        return Err(error_at_span(
                            lexer,
                            span,
                            "Must specify at least one scope",
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
        let redirect_uri = check_assigned(lexer, "redirect_uri", overall_span, redirect_uri)?;
        let scopes = check_assigned(lexer, "scopes", overall_span, scopes)?;
        let token_uri = check_assigned(lexer, "token_uri", overall_span, token_uri)?;

        Ok(Account {
            name,
            auth_cmd,
            auth_uri,
            client_id,
            client_secret,
            login_hint,
            redirect_uri,
            refresh_before_expiry: refresh_before_expiry
                .or_else(|| Some(Duration::from_secs(REFRESH_BEFORE_EXPIRY_DEFAULT))),
            refresh_at_least: refresh_at_least
                .or_else(|| Some(Duration::from_secs(REFRESH_AT_LEAST_DEFAULT))),
            scopes,
            token_uri,
        })
    }

    pub fn redirect_uri(&self, http_port: u16) -> Result<Url, Box<dyn Error>> {
        let mut url = Url::parse(&self.redirect_uri)?;
        url.set_port(Some(http_port))
            .map_err(|_| "Cannot set port")?;
        Ok(url)
    }
}

/// Given a time duration in the format `[0-9]+[dhms]` return a [Duration].
///
/// # Panics
///
/// If `t` is not in the format `[0-9]+[dhms]`.
fn time_str_to_duration(t: &str) -> Result<Duration, Box<dyn Error>> {
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
    lexer: &dyn NonStreamingLexer<DefaultLexeme<StorageT>, StorageT>,
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
    fn valid_config() {
        let c = Config::from_str(
            r#"
            notify_interval = 88m;
            refresh_retry_interval = 33s;
            account "x" {
                // Mandatory fields
                auth_uri = "http://a.com";
                client_id = "b";
                scopes = ["c", "d"];
                redirect_uri = "http://e.com";
                token_uri = "http://f.com";
                // Optional fields
                auth_cmd = "g";
                client_secret = "h";
                login_hint = "i";
                refresh_before_expiry = 42s;
                refresh_at_least = 43m;
            }
        "#,
        )
        .unwrap();
        assert_eq!(c.notify_interval, Duration::from_secs(88 * 60));
        assert_eq!(c.refresh_retry_interval, Duration::from_secs(33));

        let act = &c.accounts["x"];
        assert_eq!(act.auth_cmd, Some("g".to_owned()));
        assert_eq!(act.auth_uri, "http://a.com");
        assert_eq!(act.client_id, "b");
        assert_eq!(act.client_secret, Some("h".to_owned()));
        assert_eq!(&act.scopes, &["c".to_owned(), "d".to_owned()]);
        assert_eq!(act.redirect_uri, "http://e.com");
        assert_eq!(act.token_uri, "http://f.com");
        assert_eq!(act.login_hint, Some("i".to_owned()));
        assert_eq!(act.refresh_before_expiry, Some(Duration::from_secs(42)));
        assert_eq!(act.refresh_at_least, Some(Duration::from_secs(43 * 60)));
    }

    #[test]
    fn at_least_one_account() {
        assert_eq!(
            Config::from_str(""),
            Err("Must specify at least one account".into())
        );
    }

    #[test]
    fn invalid_time() {
        match Config::from_str("notify_interval = 18446744073709551616s;") {
            Err(s) if s.contains("Invalid time: number too large") => (),
            _ => panic!(),
        }
    }

    #[test]
    fn dup_fields() {
        match Config::from_str("notify_interval = 1s; notify_interval = 2s;") {
            Err(s) if s.contains("Mustn't specify 'notify_interval' more than once") => (),
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
    fn at_least_one_scope() {
        match Config::from_str(r#"account "x" { scopes = []; }"#) {
            Err(e) if e.contains("Must specify at least one scope") => (),
            Err(e) => panic!("{e:}"),
            _ => panic!(),
        }
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
            ("scopes", r#"["a"]"#),
            ("redirect_uri", r#""http://b.com/""#),
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
                _ => panic!(),
            }
        }
    }
}
