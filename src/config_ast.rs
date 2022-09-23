use lrpar::Span;

pub enum TopLevel {
    Account(Span, Span, Vec<AccountField>),
    AuthErrorCmd(Span),
    AuthNotifyCmd(Span),
    AuthNotifyInterval(Span),
    RefreshRetryInterval(Span),
}

pub enum AccountField {
    AuthUri(Span),
    ClientId(Span),
    ClientSecret(Span),
    LoginHint(Span),
    RedirectUri(Span),
    RefreshBeforeExpiry(Span),
    RefreshAtLeast(Span),
    Scopes(Span, Vec<Span>),
    TokenUri(Span),
}
