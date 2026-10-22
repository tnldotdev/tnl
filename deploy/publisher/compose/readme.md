# install a publisher

Keep one saved public URL serving an HTTP application after logout and restart.
These reference files require a published tnl image containing this workflow.
Set `TNL_IMAGE` to that release's complete immutable `image@sha256:…` reference;
the example deliberately supplies no invented digest or floating tag.
Compose rejects a missing image; the native publisher rejects a supplied
`TNL_IMAGE` that is not an immutable SHA-256 image reference before enrollment.

## ubuntu

Install the released `tnl` binary with its legal files, start your application,
then run as the operator who can manage the selected team:

```console
tnl publish http://127.0.0.1:4096 --name opencode --team studio --install --system
```

tnl uses your existing login or asks you to sign in. It creates or reuses the
saved hostname, preserves its visitor policy unless you explicitly configure
another policy, and enrolls a publisher with one exact public URL grant. sudo
asks for permission to copy the executable and legal files, save private root
state, and enable/start `tnl-publisher.service`. Success includes the public URL
and current publish run after a verified HTTP readiness request.

The system service uses `/var/lib/tnl/publisher` (0700), with private files and
an encrypted signing key. It contains no human control access or refresh token.
The setup journal in your client state lets an interrupted command retry with
the same scoped identity. The installed service does not need that journal or
your login at boot. Repeating setup with intact state reuses the saved URL ID.

For a configured public HTTP service with a stable address target, select its
configuration key instead of passing the target:

```console
tnl --config /srv/opencode/tnl.json publish opencode --install --system
```

Setup evaluates the configuration as the operator before sudo. It selects the
configured server, team, and public URL, and saves the target, `http.readiness.path`,
target TLS hostname, and CA contents in the job. Relative `target.tls.ca_file`
paths are resolved from the project directory, including when setup runs elsewhere.
The supervisor uses this snapshot after restart or reboot; rerun setup to change
it.

```console
tnl auth logout
sudo systemctl restart tnl-publisher.service
sudo tnl service status opencode --system
```

Systemd starts it at boot; each new publication uses a new publish run number
on the same URL. User-login installations use `--install` without `--system`.
After an abrupt stop, control may need to expire the previous run's lease first.
The supervisor retries that conflict only while its signed runtime epoch is
still current. A replaced epoch blocks; it never silently claims another epoch.

## compose

Use the maintained `compose.yaml` beside this guide as an additional file in
your application's Compose project. The application service must be named
`opencode`, listen on `0.0.0.0:4096` inside its container, and share the default
Compose network with the publisher. No application port needs to be published.

Create the saved URL once from a machine running the application, or select an
existing URL from inventory. A normal foreground publish saves its URL when
stopped with Ctrl-C:

```console
tnl publish http://127.0.0.1:4096 --name opencode --team studio
tnl url inventory --team studio
tnl publisher enroll <public-url-id> --team studio --name opencode
```

Copy `.env.example` to a private `.env` file (0600), set the released pinned
`TNL_IMAGE`, `TNL_SERVER`, and the enrollment key printed by the last command.
Keep `.env` outside source control. `TNL_TARGET=http://opencode:4096` is private
publisher configuration; the saved public URL does not store this address.

```console
docker compose --env-file .env -f compose.yaml -f /path/to/tnl/deploy/publisher/compose/compose.yaml up -d
docker compose --env-file .env -f compose.yaml -f /path/to/tnl/deploy/publisher/compose/compose.yaml logs publisher
```

The publisher runs ordinary foreground `tnl publish`. The named volume retains
its root-owned private state and signing key. After the first successful start,
remove `TNL_ENROLL_KEY` from `.env` and recreate the publisher container to remove
the consumed key from its environment. Restart/recreation with the same volume
needs no key and no human login. `unless-stopped` restarts it after Docker starts.
The volume is mounted at `/var/lib/tnl`; tnl creates the private 0700
`/var/lib/tnl/publisher` state directory within it.

Visitor access stays restricted by default: visitors need a current sign-in,
share, or visitor token permitted by the saved policy. Readiness uses a
short-lived, single-use proof bound to the current run, not an unauthenticated
application request or a policy change. Its default `/` must return 2xx.

## replace lost state

A consumed enrollment key cannot recreate a deleted signing key. A missing
volume fails with `TNL_CLIENT_PUBLISHER_ENROLLMENT_REQUIRED`. Stop the old
publisher, use `tnl publisher list --team studio` to identify and explicitly
revoke its identity with `tnl publisher revoke <publisher-id> --team studio`,
then issue a fresh `tnl publisher enroll <same-public-url-id> --team studio`.
Set the fresh key and recreate the container with a new persistent volume.
The URL ID and hostname stay the same; the new publisher's run fences older
publish runs. Stopping a container alone does not revoke its identity or grant.
Never copy a person's client state into the volume.
