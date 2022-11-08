# pizauth 0.2.0 (XXXX-XX-XX)

## Breaking changes

* `auth_error_cmd` has been renamed to `error_notify_cmd`. pizauth detects the
  (now) incorrect usage and informs the user.

* `refresh_retry_interval` has moved from a global to a per-account option.


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
