# pizauth: a background OAuth2 token requester

pizauth is a simple program for obtaining, handing out, and refreshing OAuth2
access tokens. pizauth is formed of two components: a persistent server which
interacts with the user to obtain tokens, and refreshes them as necessary; and
a command-line interface which can be used by programs such as
[fdm](https://github.com/nicm/fdm) and [msmtp](https://marlam.de/msmtp/) to
display OAuth2 access tokens.


## Quick setup

pizauth's configuration file is `~/.config/pizauth.conf`. You need to specify
at least one `account`, which tells pizauth how to authenticate against a
particular OAuth2 setup. At a minimum you need to find out from your provider:

  * The authorisation URI.
  * The token URI.
  * Your "Client ID" (and in many cases also your "Client secret"), which
    identify your software.
  * The scope(s) which your OAuth2 access token will give you access to. For
    pizauth to be able to refresh tokens, you may need to add an explicit
    `offline_access` scope.
  * The redirect URI (you must copy this *exactly*, including trailing
    slash `/` characters). If in doubt, `http://localhost/` is a common
    choice.

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
    // You don't have to specify login_hint, but it does make authentication a
    // little easier.
    login_hint = "email@example.com";
}
```

You then need to run the pizauth server:

```sh
$ pizauth server
```

and configure software to request OAuth2 tokens with `pizauth show officesmtp`.
The first time that `pizauth show officesmtp` is executed, it will print an
error to stderr that includes an authorisation URL:

```
$ pizauth show officesmtp
ERROR - Token unavailable until authorised with URL https://login.microsoftonline.com/common/oauth2/v2.0/authorize?access_type=offline&code_challenge=xpVa0mDzvR1Ozw5_cWN43DsO-k5_blQNHIzynyPfD3c&code_challenge_method=S256&scope=https%3A%2F%2Foutlook.office365.com%2FIMAP.AccessAsUser.All+https%3A%2F%2Foutlook.office365.com%2FSMTP.Send+offline_access&client_id=<your Client ID>&redirect_uri=http%3A%2F%2Flocalhost%3A14204%2F&response_type=code&state=%25E6%25A0%25EF%2503h6%25BCK&client_secret=<your Client Secret>&login_hint=email@example.com
```

The user then needs to open that URL in the browser of their choice and
complete authentication. Once complete, pizauth will be notified, and shortly
afterwards `pizauth show officesmtp` will start showing a token on stdout:

```
$ pizauth show officesmtp
DIASSPt7jlcBPTWUUCtXMWtj9TlPC6U3P3aV6C9NYrQyrhZ9L2LhyJKgl5MP7YV4
```

Note that:

  1. `pizauth show` does not block: if a token is not available it will fail;
     once a token is available it will succeed.
  2. `pizauth show` can print OAuth2 tokens which are no longer valid. By
     default, pizauth will continually refresh your token, but it may
     eventually become invalid. There will be a delay between the token
     becoming invalid and pizauth realising that has happened and notifying you
     to request a new token.


## Notification

By default, `pizauth show` displays authorisation URLs. If you prefer to be
notified asynchronously, pizauth can run arbitrary commands to alert you that
you need to authorise a new token. You will first probably want to use `show
-u` to suppress display of autherisation URLs:

```
$ pizauth show -u officesmtp
ERROR - Token unavailable until authorised with URL
```

You can then specify the global `auth_notify_cmd` setting e.g.:

```
auth_notify_cmd = "notify-send -t 30000 'pizauth authentication' \"<a href=\\\"`echo $PIZAUTH_URL | sed 's/&/&amp;/g'`\\\">$PIZAUTH_ACCOUNT</a>\"";
```

When `refresh` or `show` initiate a new token request, `auth_notify_cmd` will be
run with two environment variables set:

  * `PIZAUTH_ACCOUNT` is set to the account name to be authorised.
  * `PIZAUTH_URL` is set to the authorisation URL.

In the example above, `notify-send` is invoked, escaping `&` characters, as
XFCE's notification daemon otherwise does not parse URLs correctly. As this
suggests, users have complete flexibility within `auth_notify_cmd` to run
arbitrary shell commands.

If `auth_notify_cmd` is specified, then pizauth will periodically run
`auth_notify_cmd` for a given account until authorisation concludes
(successfully or not). The period between notifications is controlled by the
global `notify_interval = <time>;` setting which defaults to `15m` (15
minutes).

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
pizauth refresh [-c <config-path>] [-u] [<account> ... <account>]
pizauth reload [-c <config-path>]
pizauth server [-c <config-path>] [-d]
pizauth show [-c <config-path>] [-u] <account>
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

One you have pizauth set up to receive tokens, you will need to set up the software
which needs access tokens. This section contains example configuration snippets
to help you get up and running.

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
