# Systemd unit

Pizauth comes with a systemd unit. In order for it to communicate properly with
`systemd`, your `startup_cmd` in `pizauth.conf` must at some point run
`systemd-notify --ready` -- this will tell `systemd` that `pizauth` has started
up.

To start pizauth:

```sh
$ systemctl --user start pizauth.service
```

If you want `pizauth` to start on login, run

```sh
$ systemctl --user enable pizauth.service
```

(pass `--now` to also start `pizauth` with this invocation)

If you want to save pizauth's dumps encrypted and automatically restore them
when pizauth is started, you need to start/enable one of the
`pizauth-state-*.service` files provided by pizauth. For example,

```sh
$ systemctl --user enable pizauth-state-creds.service
```

Some of these units require further configuration, eg for setting the public key
and location of the private key to use for encryption. For this purpose,

```sh
$ systemctl --user edit pizauth-state-$METHOD.service
```

will open an editor in which you can configure your local edits to
`pizauth-state-$METHOD.service`. For example, you can override the default
location of the pizauth dumps (`$XDG_STATE_HOME/pizauth-state-$METHOD.dump`) to
be `~/.pizauth.dump` by inserting the following line in the `.conf` file that
`systemctl` will open:

```ini
Environment="PIZAUTH_STATE_FILE=%h/.pizauth.dump
```

See `systemd.unit(5)` for supported values of these % "specifiers".

The provided configurations are:
- `pizauth-state-creds.service`: Uses `systemd-creds` to encrypt the dumps with
  some combination of your device's TPM2 chip and a secret accessible only to
  `root`. This means the dumps generally can only be decrypted *on the device
  that encrypted them*.
- `pizauth-state-age.service`: Uses `age` to encrypt the dumps.
  Needs the `Environment="PIZAUTH_KEY_ID="` line to be set to the public key to
  encrypt with.
- `pizauth-state-gpg.service`: Uses `gpg` to encrypt the dumps.
  Needs the `Environment="PIZAUTH_KEY_ID="` line to be set to the public key to
  encrypt with. `gpg-agent` will prompt for the passphrase to unlock the key,
  which may be undesireable in nongraphical environments.
- `pizauth-state-gpg-passphrase.service`: Uses `gpg` to encrypt the dumps.
  Uses `systemd-creds` to encrypt a file containing the passphrase, which is set
  by default to be `$XDG_CONFIG_HOME/pizauth-state-gpg-passphrase.cred`.
  Needs the `Environment="PIZAUTH_KEY_ID="` line to be set to the public key to
  encrypt with. Also needs the passphrase to be stored encrypted somewhere, see
  the unit file for details.

  Note: Given the security implications here, this method is likely not much
  more secure than just using `pizauth-state-creds.service` directly.
  This unit is provided mostly to document how one might go about automatically
  passing key material relatively safely to a unit.
