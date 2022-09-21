# pizauth: a background OAuth2 token requester

pizauth is a simple program for obtaining, handing out, and refreshing OAuth2
tokens. It can be used by programs such as [fdm](https://github.com/nicm/fdm)
and [msmtp](https://marlam.de/msmtp/) to obtain OAuth2 tokens. pizauth is
formed of two components: a persistent "server" which interacts with the
user to obtain tokens, and refreshes them as necessary; and a command-line
interface which can be used by programs such as fdm and msmtp to show the
OAuth2 token for a current account.

## Quick setup

pizauth's configuration file is `~/.config/pizauth.conf`. You need to specify
at least one `account`, which tells pizauth how to authenticate against a
particular OAuth2 setup. At a minimum you need to find out from your provider:

  * The authorization URI.
  * The token URI.
  * Your "Client ID" and "Client secret", which identify your software.
  * The scope(s) which your OAuth2 token will give you access to. For
    pizauth to be able to refresh tokens, you may need to add an explicit
    `offline_access` scope.
  * The redirect URI (you must copy this *exactly*, including trailing
    slash `/` characters). If in doubt, `http://localhost/` is a common
    choice.

Unfortunately, it can be surprisingly hard to find these values out for your
provider. One option is to inspect the values in open-source clients such as
[Thunderbird](https://searchfox.org/comm-central/rev/234e91aa01d199c6b51183aa03328d556342acc8/mailnews/base/src/OAuth2Providers.jsm#126-135)
to understand what you should be looking for.

Some providers allow you to create Client IDs and Client Secrets at will (e.g.
[Google](https://console.developers.google.com/projectselector/apis/credentials)).
Some providers sometimes allow you to create Client IDs and Client Secrets
(e.g. [Microsoft
Azure](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
but allow organisations to turn off this functionality.

For example, to create an account called `officesmtp` which obtains OAuth2
tokens which allow you to read email via IMAP and send email via Office365's
servers:

```
account "officesmtp" {
    auth_uri = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
    token_uri = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
    client_id = "..."; // Fill in with your Client ID
    client_secret = "..."; // Fill in with your Client secret
    scopes = [
      "https://outlook.office365.com/IMAP.AccessAsUser.All",
      "https://outlook.office365.com/SMTP.Send",
      "offline_access"
    ];
    redirect_uri = "http://localhost/";
    auth_cmd = "notify-send pizauth \"<a href=\\\"`echo $PIZAUTH_URL | sed 's/&/&amp;/g'`\\\">officesmtp</a>\"";
    // You don't have to specify login_hint, but it does make authentication a
    // little easier.
    login_hint = "email@example.com";
}
```

You need to run the pizauth server:

```sh
$ pizauth server
```

and configure software to request OAuth2 tokens with:

```
pizauth show officesmtp
```

The first time that `show officesmtp` is executed, the shell command `auth_cmd`
will be run. In this case, `notify-send` is invoked, escaping `&` characters,
as XFCE's notification daemon otherwise does not parse URLs correctly. As this
suggests, users have complete flexibility within `auth_cmd` to run arbitrary
shell commands. When authentication is complete, `pizauth show officesmtp` will
print an OAuth2 token to `stdout` when it is called, for as long as the token
is valid.

Note that:

  1. `pizauth show` does not block: if a token is not available it will fail;
     once a token is available it will succeed.
  2. `pizauth show` can print OAuth2 tokens which are no longer valid. By
     default, pizauth will continually refresh your token, but it may
     eventually become invalid. There will be a delay between the token
     becoming invalid and pizauth realising that has happened and notifying you
     to request a new token.


## Notification

pizauth needs the user to perform authentication in order that it can obtain
OAuth tokens. The user will be periodically reminded of any
incomplete notifications, controlled by the global `notify_interval = <time>;`
setting which defaults to `15m` (15 minutes).

`<time>` is an integer followed by one of:

| Suffix | Value   |
|--------|---------|
| `s`    | seconds |
| `m`    | minutes |
| `h`    | hours   |
| `d`    | days    |


## Token refresh

OAuth2 "tokens" are actually two separate things: an "access token" which
allows you to utilise a resource (e.g. to read/send email); and a "refresh
token" which allows you to request new access tokens. `pizauth show` prints
access tokens; pizauth stores refresh tokens internally but never displays
them. Access tokens typically have a short lifetime (e.g. 1 hour) while refresh
tokens have a long lifetime (e.g. 1 week or more). By default, pizauth uses
refresh tokens to preemptively update access tokens, giving users the illusion
of continuously usable access tokens.

Each `account` has two settings relating to token refresh:

  * `refresh_before_expiry = <time>;` tells pizauth to refresh an access token
    a unit of time before it is due to expire. The default is `90s` (90
    seconds).
  * `refresh_at_least = <time>;` tells pizauth to refresh an access token a
    unit of time after it was obtained, even if the access token is not due to
    expire. The default is `90m` (90 minutes).

`refresh_at_least` is a backstop which guarantees that pizauth will notice that
an access and refresh token are no longer valid in a sensible period of time.

Refreshing can fail for temporary reasons (e.g. lack of network connectivity).
When a refresh fails for temporary reasons, pizauth will regularly retry
refreshing, controlled by the global `refresh_retry_interval` setting which
defaults to 40 seconds.

You can set these values explicitly as follows:

```
refresh_retry_interval = 40s;

account "officesmtp" {
    // Other settings as above
    refresh_before_expiry = 90s;
    refresh_at_least = 90m;
}
```


## Command-line interface

pizauth's usage is:

```
pizauth refresh [-c <config-path>] [<account> ... <account>]
pizauth reload [-c <config-path>]
pizauth server [-c <config-path>] [-dv]
pizauth show [-c <config-path>] [-v] <account>
pizauth shutdown [-c <config-path>]
```

Where:

* `pizauth refresh` tries to obtain a new access token for an account. If an
  access token already exists, a refresh is tried; if an access token doesn't
  exist, a new request is made.
* `pizauth reload` causes the server to reload its configuration (this is
  a safe equivalent of the traditional `SIGHUP` mechanism).
* `pizauth server` starts a new instance of the server.
* `pizauth show` displays an access token, if one exists, for `account`. If an
  access token does not exist, a new request is initiated.
* `pizauth shutdown` asks the server to shut itself down.


## Example integrations

One you have pizauth set up to receive tokens, you will need to set up your
mail utilities to query pizauth when an authentication token is required. This
section contains example configuration snippets to help you get up and running.

In these examples, text in chevrons (like `<this>`) needs to be edited to match
your individual setup. We also assume that `pizauth` is in `$PATH`, but if it
is not, most tools allow you to use absolute paths instead.

### msmtp

In your config file (typcially `~/.config/msmtp/config`):

```
account <account-name>
auth xoauth2
host <smtp-server>
protocol smtp
from <email-address>
user <username>
passwordeval pizauth show <pizauth-account-name>
```

### mbsync

Ensure you have the xoauth2 plugin for cyrus-sasl installed, and then use
something like this for the IMAP account in `~/.mbsyncrc`:

```
IMAPAccount <account-name>
Host <imap-server>
User <username>
PassCmd "pizauth show <pizauth-account-name>"
AuthMechs XOAUTH2
```


## Alternatives

pizauth will not be perfect for everyone. You may also wish to consider these
programs as alternatives:

* [Email OAuth 2.0 Proxy](https://github.com/simonrob/email-oauth2-proxy)
* [mailctl](https://github.com/pdobsan/mailctl)
* [mutt_oauth2.py](https://gitlab.com/muttmua/mutt/-/blob/master/contrib/mutt_oauth2.py)
