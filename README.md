# pizauth: an OAuth2 token requester daemon

pizauth is a simple program for requesting, showing, and refreshing OAuth2
access tokens. pizauth is formed of two components: a persistent server which
interacts with the user to request tokens, and refreshes them as necessary; and
a command-line interface which can be used by programs such as
[fdm](https://github.com/nicm/fdm) and [msmtp](https://marlam.de/msmtp/) to
authenticate with OAuth2.

## Quick setup

pizauth's configuration file is `~/.config/pizauth.conf`. You need to specify
at least one `account`, which tells pizauth how to authenticate against a
particular OAuth2 setup. Most users will also want to receive asynchronous
notifications of authorisation requests and errors, which requires setting
`auth_notify_cmd` and `error_notify_cmd`.


### Account setup

At a minimum you need to find out from your provider:

  * The authorisation URI.
  * The token URI.
  * Your "Client ID" (and in many cases also your "Client secret"), which
    identify your software.
  * (In some cases) The scope(s) which your OAuth2 access token will give you
    access to. For pizauth to be able to refresh tokens, you may need to add an
    explicit `offline_access` scope.
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
    auth_uri_fields = { "login_hint": "email@example.com" };
}
```

### Notifications

As standard, pizauth displays authorisation URLs and errors on stderr. If you
want to use pizauth in the background, it is easy to miss such output.
Fortunately, pizauth can run arbitrary commands to alert you that you need to
authorise a new token, in essence giving you the ability to asynchronously
display notifications. There are two main settings:

  * `auth_notify_cmd` notifies users that an account needs authenticating. The
    command is run with two environment variables set:
      * `PIZAUTH_ACCOUNT` is set to the account name to be authorised.
      * `PIZAUTH_URL` is set to the authorisation URL.
  * `error_notify_cmd` notifies users of errors.  The command is run with two
    environment variables set:
      * `PIZAUTH_ACCOUNT` is set to the account name to be authorised.
      * `PIZAUTH_MSG` is set to the error message.

For example to use pizauth with `notify-send`:

```
auth_notify_cmd = "if [[ \"$(notify-send -A \"Open $PIZAUTH_ACCOUNT\" -t 30000 'pizauth authorisation')\" == \"0\" ]]; then open \"$PIZAUTH_URL\"; fi";
error_notify_cmd = "notify-send -t 90000 \"pizauth error for $PIZAUTH_ACCOUNT\" \"$PIZAUTH_MSG\"";
```

In this example, `notify-send` is used to open a notification with a "Open
&lt;account&gt;" button; if that button is clicked, then the authorisation URL
is opened in the user's default web browser.


### Running pizauth

You need to start the pizauth server (alternatively, start `pizauth.service`,
see [systemd-unit](#systemd-unit) below):

```sh
$ pizauth server
```

and configure software to request OAuth2 tokens with `pizauth show officesmtp`.
The first time that `pizauth show officesmtp` is executed, it will print an
error to stderr that includes an authorisation URL (and, if `auth_notify_cmd`
is set, it will also execute that command):

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


## Command-line interface

pizauth's usage is:

```
pizauth dump
pizauth refresh [-u] <account>
pizauth reload
pizauth restore
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

`pizauth dump` and `pizauth restore` are explained in the
[Persistence](#persistence) section below.


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
    auth_uri_fields = { "login_hint": "<your-email-address>" };
    token_uri = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
    client_id = "<your-client-id>";
    client_secret = "<your-client-secret>";
    scopes = [
      "https://outlook.office365.com/IMAP.AccessAsUser.All",
      "https://outlook.office365.com/POP.AccessAsUser.All",
      "https://outlook.office365.com/SMTP.Send",
      "offline_access"
    ];
}
```

### Gmail

You may need to create your own client ID and secret via the [credentials
tab](https://console.cloud.google.com/apis/credentials/oauthclient/) of the
Google Cloud Console.

```
account "<your-account-name>" {
    auth_uri = "https://accounts.google.com/o/oauth2/auth";
    auth_uri_fields = {"login_hint": "<your-email-address>"};
    token_uri = "https://oauth2.googleapis.com/token";
    client_id = "<your-client-id>";
    client_secret = "<your-client-secret>";
    scopes = ["https://mail.google.com/"];
}
```

### Miele

You may need to create your own client ID and secret via the [get involved
tab](https://www.miele.com/f/com/en/register_api.aspx) of the Miele Developer
site.

No scopes are needed.

```
account "<your-account-name>" {
    auth_uri = "https://api.mcs3.miele.com/thirdparty/login/";
    token_uri = "https://api.mcs3.miele.com/thirdparty/token/";
    client_id = "<your-client-id>";
    client_secret = "<your-client-secret>";
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


## Persistence

By design, pizauth stores tokens state only in memory, and never to disk: users
never have to worry that unencrypted secrets may be accessible on disk.
However, if you use pizauth on a machine where pizauth is regularly restarted
(e.g. because the machine is regularly rebooted), reauthenticating each time
can be frustrating.

`pizauth dump` (which writes pizauth's internal token state to `stdout`) and
`pizauth restore` (which restores previously dumped token state read from
`stdin`) allow you to persist state, but since they contain secrets they
inevitably increase your security responsibilities. Although the output from
`pizauth dump` may look like it is encrypted, it is trivial for an attacker to
recover secrets from it: it is strongly recommended that you immediately
encrypt the output from `pizauth dump` to avoid possible security issues.

The most common way to call `pizauth dump` is via the `token_event_cmd`
configuration setting. `token_event_cmd` is called each time an account's
tokens change state (e.g. new tokens, refreshed tokens, etc). You can use this
to run an arbitrary shell command such as `pizauth dump`:

```
token_event_cmd = "pizauth dump | age --encrypt --output pizauth.age -R age_public_key";
```

In this example, output from `pizauth dump` is immediately encrypted using
[age](https://age-encryption.org/). In your machine's startup process you can
then call `pizauth restore` to restore the most recent dump e.g.:

```
age --decrypt -i age_private_key -o - pizauth.age | pizauth restore
```

Note that `pizauth restore` does not change the running pizauth's
configuration. Any changes in security relevant configuration between the
dumping and restoring pizauth instances cause those parts of the dump to be
silently ignored.


## Alternatives

pizauth will not be perfect for everyone. You may also wish to consider these
programs as alternatives:

* [Email OAuth 2.0 Proxy](https://github.com/simonrob/email-oauth2-proxy)
* [mailctl](https://github.com/pdobsan/mailctl)
* [mutt_oauth2.py](https://gitlab.com/muttmua/mutt/-/blob/master/contrib/mutt_oauth2.py)
* [oauth-helper-office-365](https://github.com/ahrex/oauth-helper-office-365)
