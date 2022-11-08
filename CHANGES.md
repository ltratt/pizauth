# pizauth 0.2.0 (XXXX-XX-XX)

## Breaking changes

* `auth_error_cmd` has been renamed to `error_notify_cmd`. pizauth detects the
  (now) incorrect usage and informs the user.

* `refresh_retry_interval` has been renamed to `refresh_retry` and moved from a
  global to a per-account option. Its default value remains unchanged.

## Other changes

* Tease out transitory / permanent refresh errors. Transitory errors are likely
  to be the result of temporary network problems and simply waiting for them to
  resolve is normally the best thing to do. By default, pizauth will wait
  arbitrarily long for transitory errors to resolve.

  Users who wish to check that transitory errors really are transitory can set
  the `expect_transitory_errors_if` setting. This is a shell command that, if
  it returns a zero exit code, signifies that transitory errors are permanent
  and that an access token should be invalidated. If available, `nc -z
  <website> <port>` is a good setting. `expect_transitory_errors_if` is
  designed to be fail-safe in that if the shell command fails unnecessarily
  (e.g. if you specify `ping` on a network that prevents ping traffic), pizauth
  will invalidate the access token.

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
