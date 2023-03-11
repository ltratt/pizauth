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
