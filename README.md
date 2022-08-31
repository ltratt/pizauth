# pizauth: a background OAuth2 token requester

pizauth is a simple program for obtaining, handing out, and refreshing OAuth2
tokens. It can be used by programs such as [fdm](https://github.com/nicm/fdm)
and [msmtp](https://marlam.de/msmtp/) to obtain OAuth2 tokens. pizauth is
formed of two components: a persistent "server" which requests tokens and
interacts with the user when necessary; a command-line interface which can used
by programs such as fdm and msmtp to show the OAuth2 token for a current
account.

## Quick setup

pizauth's configuration file is `~/.config/pizauth.conf`. You need to specify
at least one `account`, which tells pizauth how to authenticate against a
particular OAuth2 setup. Unfortunately it can be rather tedious to work out
exactly what you need. At a minimum you need to find out from your provider:

  * The authorization URI.
  * The token URI.
  * Your "Client ID" and "Client secret", which identify your software.
  * The scope(s) which your OAuth2 token will give you access to.
  * The redirect URI (you must copy this *exactly*, including trailing
    slash `/` characters).

Unfortunately, it can be surprisingly hard to find these values out for your
provider. One option is to inspect the values in open-source clients such as
[Thunderbird](https://searchfox.org/comm-central/rev/234e91aa01d199c6b51183aa03328d556342acc8/mailnews/base/src/OAuth2Providers.jsm#126-135)
for inspiration.

Some providers allow you to create Client IDs and Client Secrets at will (e.g.
[Google](https://console.developers.google.com/projectselector/apis/credentials)).
Some providers sometimes allow you to create Client IDs and Client Secrets but
allow organisations to turn off this functionality (e.g. [Microsoft
Azure](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).

For example, to create an account called `officesmtp` which obtains OAuth2
tokens which allow you to send email via Office365's SMTP servers, 

```
account "officesmtp" {
    // Mandatory fields
    auth_uri = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
    token_uri = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
    client_id = "..."; // Fill in with your Client ID
    client_secret = "..."; // Fill in with your Client secret
    scopes = ["https://outlook.office365.com/SMTP.Send", "offline_access"];
    redirect_uri = "http://localhost/";
    // Optional fields
    login_hint = "email@example.com";
    refresh_before_expiry = 1m;
    refresh_at_least = 90m;
}
```

Note that Azure requires a non-standards `offline_access` scope to be added so
that pizauth can refresh OAuth tokens.

`login_hint` can make the verification of your OAuth2 token easier.
`refresh_before_expiry` causes pizauth to attempt to refresh tokens 1 minute
before they are due to expire, so that pizauth can generally give the illusion
of permanently available tokens. `refresh_at_least` causes pizauth to try
refreshing a token at least every 90 minutes so that if a token is no longer
valid, pizauth can notify the user.

You then need to run the pizauth server:

```sh
$ pizauth server
```

and then configure your program to request OAuth2 tokens with:

```
pizauth show officesmtp
```

The first time that `show smtp` is executed, pizauth will show a notification
to the user including a URL. That URL needs to be opened in a browser, and the
authentication process completed. When authentication is complete, you will see
the message "pizauth successfully received authentication code" in your
browser. `pizauth show officesmtp` will now print an OAuth2 token to `stdout`
when it is called, for as long as the token is valid.

Note that:

  1. `pizauth show` does not block: if a token is not available it will fail;
     once a token is available it will succeed.
  2. `pizauth show` can print out OAuth2 tokens which are no longer valid. If
     you have set (as is recommended) `refresh_at_least` then pizauth will
     notice the token's lack of validity, and require the user to authenticate
     to give pizauth a new token.
