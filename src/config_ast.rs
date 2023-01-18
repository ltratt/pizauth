use lrpar::Span;

pub enum TopLevel {
    Account(Span, Span, Vec<AccountField>),
    AuthErrorCmd(Span),
    AuthNotifyCmd(Span),
    AuthNotifyInterval(Span),
    ErrorNotifyCmd(Span),
    HttpListen(Span),
    NotTransientErrorIf(Span),
}

pub enum AccountField {
    AuthUri(Span),
    ClientId(Span),
    ClientSecret(Span),
    LoginHint(Span),
    NotTransientErrorIf(Span),
    RedirectUri(Span),
    RefreshAtLeast(Span),
    RefreshBeforeExpiry(Span),
    RefreshRetry(Span),
    Scopes(Span, Vec<Span>),
    TokenUri(Span),
}
