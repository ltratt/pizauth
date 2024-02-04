# pizauth 1.0.4 (2023-02-04)

* Add `pizauth revoke` which revokes any tokens / ongoing authentication for a
  given account. Note that this does *not* revoke the remote token, as OAuth2
  does not currently have standard support for this.

* Include bash completion scripts and example systemd units.

* Rework file installation to better handle a variety of OSes and file layouts.
  The Makefile is now only compatible with gmake.


# pizauth 1.0.3 (2023-11-28)

* Add `pizauth status` to see which accounts have valid tokens (or not):
  ```
  $ pizauth status
  act1: No access token
  act2: Active access token (obtained Sat, 4 Nov 2023 21:52:11 +0000; expires Sat, 4 Nov 2023 23:20:42 +0000)
  act3: Active access token (obtained Sat, 4 Nov 2023 22:23:03 +0000; expires Mon, 4 Dec 2023 22:23:03 +0000)
  ```

* Give better syntax errors if backslashes (`\\`) are used incorrectly.


# pizauth 1.0.2 (2023-10-12)

* Better handle syntactically invalid requests. In particular, this causes the
  check for a running instance of pizauth not to cause the existing instance to
  exit.

* Document `-v` (which can be repeated up to 4 times for increased verbosity)
  on `pizauth server`.


# pizauth 1.0.1 (2023-08-14)

* Fix location of `ring` dependency.


# pizauth 1.0.0 (2023-08-13)

* First stable release.

* Add `pizauth info [-j]` which informs the user where pizauth is looking for
  configuration files and so on. For example:

  ```
  $ pizauth info
  pizauth version 0.3.0:
    cache directory: /home/ltratt/.cache/pizauth
    config file: /home/ltratt/.config/pizauth.conf
  ```

  Adding `-j` outputs the same information in JSON format for integration with
  external tools. The `info_format_version` field is an integer value
  specifying the version of the JSON output: if incompatible changes are made,
  this integer will be monotonically increased.


# pizauth 0.3.0 (2023-05-29)

## Breaking changes

* `not_transient_error_if` has been removed as a global and per-account option.
  In its place is a new global option `transient_error_if_cmd`.

  If you have an existing `not_transient_error_if` option, you will need
  to reconsider the shell command you execute. One possibility is to change:

  ```
  not_transient_error_if = "shell-cmd";
  ```
  
  to:
  
  ```
  transient_error_if_cmd = "! shell-cmd";
  ```

  `transient_error_if_cmd` sets the environment variable `$PIZAUTH_ACCOUNT` to
  allow you to perform different actions for different accounts if you desire.


# pizauth 0.2.2 (2023-04-03)

* Added a global `token_event_cmd` option, which runs a command whenever an
  account's token changes state.

* Added `pizauth dump` and `pizauth restore` which dump and restore pizauth's
  token state respectively. When combined with `token_event_cmd`, these allow
  users to persist token state. The output from `pizauth dump` is not
  meaningfully encrypted: it is the user's responsibility to encrypt, or
  otherwise secure, the dump output.

* Update an account's refresh token if it is sent to pizauth by the remote
  server.

* Move from the unmaintained `json` to the `serde_json` crate.

* Don't bother users with OAuth2 "errors" (e.g. that a token cannot be
  refreshed) that are better thought of as an inevitable part of the OAuth2
  lifecycle.


# pizauth 0.2.1 (2023-03-11)

* `login_hint` is now deprecated in favour of the more general `auth_uri_fields`.
  Change:

  ```
  login_hint = "email@example.com";
  ```
  
  to:
  
  ```
  auth_uri_fields = { "login_hint": "email@example.com" };
  ```

  Currently `login_hint` is silently transformed into the equivalent
  `auth_uri_fields` for backwards compatibility.

* `auth_uri_fields` allows users to specify zero or more key/value pairs to be
  appended to the authorisation URI. Keys (and their values) are appended
  in the order they appear in `auth_uri_fields`, each separated by a `&`. The
  same key may be specified multiple times.

* Several options can now be set globally and overridden in individual accounts:
    * `not_transient_error_if`
    * `refresh_at_least`
    * `refresh_before_expiry`
    * `refresh_retry`

* `scopes` is now optional and also, equivalently, can be empty.

# pizauth 0.2.0 (2022-12-14)

## Breaking changes

* `auth_error_cmd` has been renamed to `error_notify_cmd`. pizauth detects the
  (now) incorrect usage and informs the user.

* `refresh_retry_interval` has been renamed to `refresh_retry` and moved from a
  global to a per-account option. Its default value remains unchanged.

## Other changes

* Tease out transitory / permanent refresh errors. Transitory errors are likely
  to be the result of temporary network problems and simply waiting for them to
  resolve is normally the best thing to do. By default, pizauth thus simply
  ignores transitory errors.

  Users who wish to check that transitory errors really are transitory can set
  `not_transitory_error_if` setting. This is a shell command that, if
  it returns a zero exit code, signifies that transitory errors are
  permanent and that an access token should be invalidated. `nc -z <website>
  <port>` is an example of a reasonable setting. `not_transitory_error_if` is
  fail-safe in that if the shell command fails unnecessarily (e.g. if you
  specify `ping` on a network that prevents ping traffic), pizauth will
  invalidate the access token.

* Each refresh of an account now happens in a separate thread, so stalled
  refreshing cannot affect other accounts.

* Fix bug where newly authorised access tokens were immediately refreshed.


# pizauth 0.1.1 (2022-10-20)

Second alpha release.

* Added global `http_listen` option to fix the IP address and port pizauth's
  HTTP server listens on. This is particularly useful when running pizauth on a
  remote machine, since it makes it easy to open an `ssh -L` tunnel to
  authenticate that remote instance.

* Fix build on OS X by ignoring deprecation warnings for the `daemon` function.

* Report config errors before daemonisation.


# pizauth 0.1.0 (2022-09-29)

First alpha release.
