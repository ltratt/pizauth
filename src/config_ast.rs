use lrpar::Span;

pub enum TopLevel {
    Account(Span, Span, Vec<AccountField>),
}

pub enum AccountField {
    AuthUri(Span),
    ClientId(Span),
    ClientSecret(Span),
    LoginHint(Span),
    RedirectUri(Span),
    Scopes(Span, Vec<Span>),
    TokenUri(Span),
}
