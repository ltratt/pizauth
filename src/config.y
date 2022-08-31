%start TopLevels
%avoid_insert "INT" "STRING"
%epp TIME "<time>[dhms]"

%%

TopLevels -> Result<Vec<TopLevel>, ()>:
    TopLevels TopLevel { flattenr($1, $2) }
  | { Ok(vec![]) }
  ;

TopLevel -> Result<TopLevel, ()>:
    "ACCOUNT" "STRING" "{" AccountFields "}" { Ok(TopLevel::Account(overall_span($1, $5), map_err($2)?, $4?)) }
  | "RENOTIFY" "=" "TIME" ";" { Ok(TopLevel::Renotify(map_err($3)?)) }
  ;

AccountFields -> Result<Vec<AccountField>, ()>:
    AccountFields AccountField { flattenr($1, $2) }
  | { Ok(vec![]) }
  ;

AccountField -> Result<AccountField, ()>:
    "AUTH_URI" "=" "STRING" ";" { Ok(AccountField::AuthUri(map_err($3)?)) }
  | "CLIENT_ID" "=" "STRING" ";" { Ok(AccountField::ClientId(map_err($3)?)) }
  | "CLIENT_SECRET" "=" "STRING" ";" { Ok(AccountField::ClientSecret(map_err($3)?)) }
  | "LOGIN_HINT" "=" "STRING" ";" { Ok(AccountField::LoginHint(map_err($3)?)) }
  | "REDIRECT_URI" "=" "STRING" ";" { Ok(AccountField::RedirectUri(map_err($3)?)) }
  | "REFRESH_BEFORE_EXPIRY" "=" "TIME" ";" { Ok(AccountField::RefreshBeforeExpiry(map_err($3)?)) }
  | "REFRESH_AT_LEAST" "=" "TIME" ";" { Ok(AccountField::RefreshAtLeast(map_err($3)?)) }
  | "SCOPES" "=" "[" Scopes "]" ";" { Ok(AccountField::Scopes($1.unwrap_or_else(|x| x).span(), $4?)) }
  | "TOKEN_URI" "=" "STRING" ";" { Ok(AccountField::TokenUri(map_err($3)?)) }
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

fn overall_span(
  from: Result<DefaultLexeme<StorageT>, DefaultLexeme<StorageT>>,
  to: Result<DefaultLexeme<StorageT>, DefaultLexeme<StorageT>>
) -> Span {
    let from = from.unwrap_or_else(|x| x).span();
    let to = to.unwrap_or_else(|x| x).span();
    Span::new(from.start(), to.end())
}

/// Flatten `rhs` into `lhs`.
fn flattenr<T>(lhs: Result<Vec<T>, ()>, rhs: Result<T, ()>) -> Result<Vec<T>, ()> {
    let mut flt = lhs?;
    flt.push(rhs?);
    Ok(flt)
}
