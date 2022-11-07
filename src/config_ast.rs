use lrpar::Span;

pub enum TopLevel {
    Account(Span, Span, Vec<AccountField>),
    AuthErrorCmd(Span),
    AuthNotifyCmd(Span),
    AuthNotifyInterval(Span),
    ExpectTransientErrorsIf(Span),
    HttpListen(Span),
    RefreshWarnCmd(Span),
    RefreshWarnInterval(Span),
}

pub enum AccountField {
    AuthUri(Span),
    ClientId(Span),
    ClientSecret(Span),
    LoginHint(Span),
    RedirectUri(Span),
    RefreshAtLeast(Span),
    RefreshBeforeExpiry(Span),
    RefreshRetry(Span),
    Scopes(Span, Vec<Span>),
    TokenUri(Span),
}
