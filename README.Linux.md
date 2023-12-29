# pizauth on Linux

Pizauth comes with a systemd unit and example configurations. To start pizauth:

```sh
$ systemctl --user start pizauth.service
```

If you want `pizauth` to start on login, run

```sh
$ systemctl --user enable pizauth.service
```

In `/usr/share/examples/pizauth/systemd-dropins` are templates for saving
pizauth dumps encrypted with `age` and `gpg`. To use them, run

```sh
$ systemctl --user edit pizauth.service
```

and paste whichever of the templates suits you in the file `systemctl` opens.
Make sure to modify the references to private/public keys/IDs in the temalpte
file to point to your keys/IDs.
