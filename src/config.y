%start TopLevels
%avoid_insert "STRING"
%epp TIME "<time>[dhms]"
%expect-unused Unmatched "UNMATCHED"

%%

TopLevels -> Result<Vec<TopLevel>, ()>:
    TopLevels TopLevel { flattenr($1, $2) }
  | { Ok(vec![]) }
  ;

TopLevel -> Result<TopLevel, ()>:
    "ACCOUNT" "STRING" "{" AccountFields "}" { Ok(TopLevel::Account($span, map_err($2)?, $4?)) }
  | "AUTH_ERROR_CMD" "=" "STRING" ";" { Ok(TopLevel::AuthErrorCmd($span)) }
  | "AUTH_NOTIFY_CMD" "=" "STRING" ";" { Ok(TopLevel::AuthNotifyCmd(map_err($3)?)) }
  | "AUTH_NOTIFY_INTERVAL" "=" "TIME" ";" { Ok(TopLevel::AuthNotifyInterval(map_err($3)?)) }
  | "ERROR_NOTIFY_CMD" "=" "STRING" ";" { Ok(TopLevel::ErrorNotifyCmd(map_err($3)?)) }
  | "HTTP_LISTEN" "=" "NONE" ";" { Ok(TopLevel::HttpListenNone(map_err($3)?)) }
  | "HTTP_LISTEN" "=" "STRING" ";" { Ok(TopLevel::HttpListen(map_err($3)?)) }
  | "HTTPS_LISTEN" "=" "NONE" ";" { Ok(TopLevel::HttpsListenNone(map_err($3)?)) }
  | "HTTPS_LISTEN" "=" "STRING" ";" { Ok(TopLevel::HttpsListen(map_err($3)?)) }
  | "TRANSIENT_ERROR_IF_CMD" "=" "STRING" ";" { Ok(TopLevel::TransientErrorIfCmd(map_err($3)?)) }
  | "REFRESH_AT_LEAST" "=" "TIME" ";" { Ok(TopLevel::RefreshAtLeast(map_err($3)?)) }
  | "REFRESH_BEFORE_EXPIRY" "=" "TIME" ";" { Ok(TopLevel::RefreshBeforeExpiry(map_err($3)?)) }
  | "REFRESH_RETRY" "=" "TIME" ";" { Ok(TopLevel::RefreshRetry(map_err($3)?)) }
  | "STARTUP_CMD" "=" "STRING" ";" { Ok(TopLevel::StartupCmd(map_err($3)?)) }
  | "TOKEN_EVENT_CMD" "=" "STRING" ";" { Ok(TopLevel::TokenEventCmd(map_err($3)?)) }
  ;

AccountFields -> Result<Vec<AccountField>, ()>:
    AccountFields AccountField { flattenr($1, $2) }
  | { Ok(vec![]) }
  ;

AccountField -> Result<AccountField, ()>:
    "AUTH_URI" "=" "STRING" ";" { Ok(AccountField::AuthUri(map_err($3)?)) }
  | "AUTH_URI_FIELDS" "=" "{" AuthUriFields "}" ";" { Ok(AccountField::AuthUriFields($1.unwrap_or_else(|x| x).span(), $4?)) }
  | "CLIENT_ID" "=" "STRING" ";" { Ok(AccountField::ClientId(map_err($3)?)) }
  | "CLIENT_SECRET" "=" "STRING" ";" { Ok(AccountField::ClientSecret(map_err($3)?)) }
  | "LOGIN_HINT" "=" "STRING" ";" { Ok(AccountField::LoginHint(map_err($3)?)) }
  | "REDIRECT_URI" "=" "STRING" ";" { Ok(AccountField::RedirectUri(map_err($3)?)) }
  | "REFRESH_AT_LEAST" "=" "TIME" ";" { Ok(AccountField::RefreshAtLeast(map_err($3)?)) }
  | "REFRESH_BEFORE_EXPIRY" "=" "TIME" ";" { Ok(AccountField::RefreshBeforeExpiry(map_err($3)?)) }
  | "REFRESH_RETRY" "=" "TIME" ";" { Ok(AccountField::RefreshRetry(map_err($3)?)) }
  | "SCOPES" "=" "[" Scopes "]" ";" { Ok(AccountField::Scopes($1.unwrap_or_else(|x| x).span(), $4?)) }
  | "TOKEN_URI" "=" "STRING" ";" { Ok(AccountField::TokenUri(map_err($3)?)) }
  ;

AuthUriFields -> Result<Vec<(Span, Span)>, ()>:
    AuthUriFields "," "STRING" ":" "STRING" {
      let mut spans = $1?;
      spans.push((map_err($3)?, map_err($5)?));
      Ok(spans)
    }
  | "STRING" ":" "STRING" { Ok(vec![(map_err($1)?, map_err($3)?)]) }
  | { Ok(vec![]) }
  ;

Scopes -> Result<Vec<Span>, ()>:
    Scopes "," "STRING" {
      let mut spans = $1?;
      spans.push(map_err($3)?);
      Ok(spans)
    }
  | "STRING" { Ok(vec![map_err($1)?]) }
  | { Ok(vec![]) }
  ;

// This rule helps turn lexing errors into parsing errors.
Unmatched -> ():
    "UNMATCHED" { }
  ;

%%

use lrlex::DefaultLexeme;
use lrpar::Span;

type StorageT = u8;

use crate::config_ast::{AccountField, TopLevel};

fn map_err(r: Result<DefaultLexeme<StorageT>, DefaultLexeme<StorageT>>)
    -> Result<Span, ()>
{
    r.map(|x| x.span()).map_err(|_| ())
}

/// Flatten `rhs` into `lhs`.
fn flattenr<T>(lhs: Result<Vec<T>, ()>, rhs: Result<T, ()>) -> Result<Vec<T>, ()> {
    let mut flt = lhs?;
    flt.push(rhs?);
    Ok(flt)
}
