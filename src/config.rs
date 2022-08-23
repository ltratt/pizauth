use std::{collections::HashMap, error::Error, fs::read_to_string, path::Path, time::Duration};

use lrlex::{lrlex_mod, DefaultLexeme, LRNonStreamingLexer};
use lrpar::{lrpar_mod, NonStreamingLexer, Span};
use url::Url;

use crate::config_ast;

type StorageT = u8;

lrlex_mod!("config.l");
lrpar_mod!("config.y");

pub struct Config {
    pub accounts: HashMap<String, Account>,
}

impl Config {
    /// Create a `Config` from `path`, returning `Err(String)` (containing a human readable
    /// message) if it was unable to do so.
    pub fn from_path(conf_path: &Path) -> Result<Self, String> {
        let input = match read_to_string(conf_path) {
            Ok(s) => s,
            Err(e) => return Err(format!("Can't read {:?}: {}", conf_path, e)),
        };

        let lexerdef = config_l::lexerdef();
        let lexer = lexerdef.lexer(&input);
        let (astopt, errs) = config_y::parse(&lexer);
        if !errs.is_empty() {
            let msgs = errs
                .iter()
                .map(|e| e.pp(&lexer, &config_y::token_epp))
                .collect::<Vec<_>>();
            return Err(msgs.join("\n"));
        }

        let mut accounts = HashMap::new();
        match astopt {
            Some(Ok(opts)) => {
                for opt in opts {
                    match opt {
                        config_ast::TopLevel::Account(overall_span, name, fields) => {
                            accounts.insert(
                                unescape_str(lexer.span_str(name)),
                                Account::from_fields(&lexer, overall_span, fields)?,
                            );
                        }
                    }
                }
            }
            _ => unreachable!(),
        }

        Ok(Config { accounts })
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

pub struct Account {
    pub auth_uri: String,
    pub client_id: String,
    pub client_secret: String,
    pub login_hint: Option<String>,
    redirect_uri: String,
    pub refresh_before_expiry: Option<Duration>,
    pub refresh_at_least: Option<Duration>,
    pub scopes: Vec<String>,
    pub token_uri: String,
}

impl Account {
    fn from_fields(
        lexer: &LRNonStreamingLexer<DefaultLexeme<StorageT>, StorageT>,
        overall_span: Span,
        fields: Vec<config_ast::AccountField>,
    ) -> Result<Self, String> {
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
                config_ast::AccountField::AuthUri(span) => {
                    auth_uri = Some(check_not_assigned_str(lexer, "auth_uri", span, auth_uri)?)
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
                    token_uri = Some(check_not_assigned_str(lexer, "token_uri", span, token_uri)?)
                }
            }
        }

        let auth_uri = check_assigned(lexer, "auth_uri", overall_span, auth_uri)?;
        let client_id = check_assigned(lexer, "client_id", overall_span, client_id)?;
        let client_secret = check_assigned(lexer, "client_secret", overall_span, client_secret)?;
        let redirect_uri = check_assigned(lexer, "redirect_uri", overall_span, redirect_uri)?;
        let scopes = check_assigned(lexer, "scopes", overall_span, scopes)?;
        let token_uri = check_assigned(lexer, "token_uri", overall_span, token_uri)?;

        Ok(Account {
            auth_uri,
            client_id,
            client_secret,
            login_hint,
            redirect_uri,
            refresh_before_expiry,
            refresh_at_least,
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
}
