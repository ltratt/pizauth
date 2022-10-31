# pizauth: an OAuth2 token requester daemon

pizauth is a simple program for requesting, showing, and refreshing OAuth2
access tokens. pizauth is formed of two components: a persistent server which
interacts with the user to request tokens, and refreshes them as necessary; and
a command-line interface which can be used by programs such as
[fdm](https://github.com/nicm/fdm) and [msmtp](https://marlam.de/msmtp/) to
authenticate with OAuth2. Tokens are only ever stored in memory and are never
persisted to disk.


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
  * (In some cases) The redirect URI (you must copy this *exactly*, including
    trailing slash `/` characters). The default value of `http://localhost/`
    suffices in most instances.

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


## Notifications

### Authorisation notifications

By default, `pizauth show` displays authorisation URLs on stdout. Depending on
how and where you use pizauth, you might not notice this output. Fortunately,
pizauth can run arbitrary commands to alert you that you need to authorise a
new token, in essence giving you the ability to asynchronously display
notifications. You will first probably want to use `show -u` to suppress
display of authorisation URLs:

```
$ pizauth show -u officesmtp
ERROR - Token unavailable until authorised with URL
```

You can then specify the global `auth_notify_cmd` setting e.g.:

```
auth_notify_cmd = "notify-send -t 30000 'pizauth authentication' \"<a href=\\\"`echo $PIZAUTH_URL | sed 's/&/&amp;/g'`\\\">$PIZAUTH_ACCOUNT</a>\"";
```

When `refresh` or `show` initiate a new token request, `auth_notify_cmd` is run
with two environment variables set:

  * `PIZAUTH_ACCOUNT` is set to the account name to be authorised.
  * `PIZAUTH_URL` is set to the authorisation URL.

In the example above, `notify-send` is invoked, escaping `&` characters, as
XFCE's notification daemon otherwise does not parse URLs correctly. As this
suggests, users have complete flexibility within `auth_notify_cmd` to run
arbitrary shell commands.

If `auth_notify_cmd` is specified, then pizauth will periodically run
`auth_notify_cmd` for a given account until authorisation concludes
(successfully or not). The period between notifications is controlled by the
global `auth_notify_interval = <time>;` setting which defaults to `15m` (15
minutes).

`<time>` is an integer followed by one of:

| Suffix | Value   |
|--------|---------|
| `s`    | seconds |
| `m`    | minutes |
| `h`    | hours   |
| `d`    | days    |


### Error notifications

pizauth reports authentication errors via syslog by default. To override this
you can set the global `auth_error_cmd` setting e.g.:

```
auth_error_cmd = "notify-send -t 90000 \"pizauth error for $PIZAUTH_ACCOUNT\" \"$PIZAUTH_MSG\"";
```

`auth_error_cmd` is run with two environment variables set:

  * `PIZAUTH_ACCOUNT` is set to the account name to be authorised.
  * `PIZAUTH_MSG` is set to the error message.


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

  * `refresh_at_least = <time>;` tells pizauth to refresh an access token a
    unit of time after it was obtained, even if the access token is not due to
    expire. The default is `90m` (90 minutes).
  * `refresh_before_expiry = <time>;` tells pizauth to refresh an access token
    a unit of time before it is due to expire. The default is `90s` (90
    seconds).

`refresh_at_least` is a backstop which guarantees that pizauth will notice that
an access and refresh token are no longer valid in a sensible period of time.

Refreshing can fail for temporary reasons (e.g. lack of network connectivity).
When a refresh fails for temporary reasons, pizauth will regularly retry
refreshing, controlled by the `refresh_retry` setting which defaults to 40
seconds.

You can set these values explicitly as follows:

```

account "officesmtp" {
    // Other settings as above
    refresh_at_least = 90m;
    refresh_before_expiry = 90s;
    refresh_retry = 40s;
}
```


## Command-line interface

pizauth's usage is:

```
pizauth refresh [-u] <account>
pizauth reload
pizauth server [-c <config-path>] [-d]
pizauth show [-u] <account>
pizauth shutdown
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

Once you have set up pizauth, you will then need to set up the software which
needs access tokens. This section contains example configuration snippets to
help you get up and running.

In these examples, text in chevrons (like `<this>`) needs to be edited to match
your individual setup. The examples assume that `pizauth` is in your `$PATH`:
if it is not, you will need to substitute an absolute path to `pizauth` in
these snippets.

### msmtp

In your configuration file (typically `~/.config/msmtp/config`):

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


## Example account settings

Each provider you wish to authenticate with will have its own settings it
requires of you. These can be difficult to find, so examples are provided in
this section. Caveat emptor: these settings will not work in all situations,
and providers have historically required users to intermittently change their
settings.

### Microsoft / Exchange

You may need to create your own client ID and secret by registering with
Microsoft's [identity
platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).

```
account "<your-account-name>" {
    auth_uri = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
    token_uri = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
    client_id = "<your-client-id>";
    client_secret = "<your-client-secret>";
    scopes = [
      "https://outlook.office365.com/IMAP.AccessAsUser.All",
      "https://outlook.office365.com/POP.AccessAsUser.All",
      "https://outlook.office365.com/SMTP.Send",
      "offline_access"
    ];
    login_hint = "<your-email-address>";
}
```

### Gmail

You may need to create your own client ID and secret via the [credentials
tab](https://console.cloud.google.com/apis/credentials/oauthclient/) of the
Google Cloud Console.

```
account "<your-account-name>" {
    auth_uri = "https://accounts.google.com/o/oauth2/auth";
    token_uri = "https://oauth2.googleapis.com/token";
    client_id = "<your-client-id>";
    client_secret = "<your-client-secret>";
    scopes = ["https://mail.google.com/"];
    login_hint = "<your-email-address>";
}
```


## pizauth on a remote machine

You can run pizauth on a remote machine and have your local machine
authenticate that remote existence with `ssh -L`. pizauth contains a small HTTP
server used to receive authentication requests. By default the HTTP server
listens on a random port, but it is easiest in this scenario to fix a port with
the global `http_listen` option:

```
http_listen = "127.0.0.1:<port-number>";
account "..." { ... }
```

Then on your local machine (using the same `<port-number>` as above run `ssh`:

```
ssh -L 127.0.0.1:<port-number>:127.0.0.1:<port-number> <remote>
```

Then on the remote machine start `pizauth server` and then `pizauth show
<account-name>`. Copy the authentication URL into a browser on your local
machine and continue as normal. When you see the "pizauth processing
authentication: you can safely close this page." message you can close the
`ssh` tunnel. If the account later needs reauthenticating (e.g. because the
refresh token has become invalid), simply reopen the `ssh` tunnel,
reauthenticate, and close the `ssh` tunnel.


## Alternatives

pizauth will not be perfect for everyone. You may also wish to consider these
programs as alternatives:

* [Email OAuth 2.0 Proxy](https://github.com/simonrob/email-oauth2-proxy)
* [mailctl](https://github.com/pdobsan/mailctl)
* [mutt_oauth2.py](https://gitlab.com/muttmua/mutt/-/blob/master/contrib/mutt_oauth2.py)
* [oauth-helper-office-365](https://github.com/ahrex/oauth-helper-office-365)
