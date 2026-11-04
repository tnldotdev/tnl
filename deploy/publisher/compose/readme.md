# keep an app online

Run a publisher as a system service or beside your app in Docker Compose. It
keeps the same public URL after you log out or restart the machine.

You'll need a released `tnl` binary, an app that is already running, and permission
to manage its tnl team. Visitors still need access under the saved URL's policy.

## on ubuntu

Install the released binary with its accompanying legal files, then run this as
your normal user:

```sh
tnl publish http://127.0.0.1:4096 --name opencode --team studio --install --system
```

tnl asks you to sign in if needed, saves the URL, and uses sudo to install
`tnl-publisher.service`. The app's readiness path, `/` by default, must return 2xx.

systemd starts the publisher at boot. Its identity lives in
`/var/lib/tnl/publisher`, separate from your login. Keep that private directory
across restarts.

```sh
sudo systemctl restart tnl-publisher.service
sudo tnl service status opencode --system
```

If the app is already declared in project configuration, select its service:

```sh
tnl --config /srv/opencode/tnl.json publish opencode --install --system
```

Installation saves the target and TLS settings. Rerun it after changing them.
Omit `--system` for a service that starts when you log in.

## with docker compose

The example expects an app service named `opencode`, listening on
`0.0.0.0:4096` on the same Compose network. You don't need to publish its port.
Change `TNL_TARGET` if your service has another name or port.

First, choose a saved URL. If you don't have one, publish from a machine that
can reach the app, then press Ctrl-C; the URL stays saved:

```sh
tnl publish http://127.0.0.1:4096 --name opencode --team studio
tnl url inventory --team studio
tnl publisher enroll <public-url-id> --team studio --name opencode
```

Copy this directory's `.env.example` to a private `.env` in your app's Compose
directory. Set `TNL_SERVER` to the same server used above, `TNL_IMAGE` to a
published `image@sha256:...` reference, and `TNL_ENROLL_KEY` to the key just printed.
Keep `.env` out of Git.

```sh
chmod 600 .env
docker compose --env-file .env -f compose.yaml -f /path/to/tnl/deploy/publisher/compose/compose.yaml up -d
docker compose --env-file .env -f compose.yaml -f /path/to/tnl/deploy/publisher/compose/compose.yaml logs publisher
```

After the first successful start, remove `TNL_ENROLL_KEY` from `.env` and rerun
the `up -d` command. The key is one-use; later starts use the identity in the
`publisher-state` volume at `/var/lib/tnl/publisher`.

Keep that volume. If it is lost, stop the old publisher, revoke its identity, and
enroll a replacement for the same URL:

```sh
tnl publisher list --team studio
tnl publisher revoke <publisher-identity-id> --team studio
tnl publisher enroll <same-public-url-id> --team studio --name opencode
```

Put the new enrollment key in `.env` and start with a new persistent volume.
Use publisher enrollment rather than copying your personal client state.
