# can we keep this alive?

Open `start.keepthisalive.com` to start a browser host. Keep the tab open.
`keepthisalive.com` gets its files from browser hosts. If the last one stops,
the site returns `503`; the start page can bring it back.

The Cloudflare proxy checks every file against a fixed release manifest. It
doesn't fall back to the start page's copy. Hosts share who they can reach,
the earliest start time they remember, and when they're starting another host.
There's no central waiting list. tnl runs the tunnels and checks publication
permissions.

The site includes [Fira Code](https://github.com/tonsky/FiraCode). Hosts pass
the font along with the other files; the browser doesn't contact a font service.

## run it

From the repository root:

```sh
mise exec -- task js:keepalive:preview  # page only; no tunnels
mise exec -- task js:keepalive:test    # gossip and file checks
mise exec -- task js:keepalive:dev FLAGS='--var START_HOST:localhost'
```

With the last command, open `http://localhost:8787` for the start page. With no
tnl credentials configured, it won't publish. `http://127.0.0.1:8787` takes the
normal proxy path, which returns `503` when there are no hosts.

## browser handoff

Use a disposable tnl deployment named `keepalive` with a public, anonymous HTTP
service named `site`, multiple publishers enabled, and exact-run addresses under
`hosts.keepthisalive.com`. Set `SITE_ORIGIN`, `START_HOST`, and `SHARED_HOST`
to the test addresses (`https://prod.hosts.keepthisalive.com` is the production
shared service). Set `PROJECT_KEY`,
`TEAM_ID`, `CONTROL_URL`, and a scoped `MANAGEMENT_TOKEN` secret so the proxy can
request one-use enrollment keys for `site`. Configure the test hostnames and
enrollment rate limits before giving the start page a public URL.

Use tnl-managed certificates if the test deployment supports them. For the
shared wildcard, the proxy can supply `CERTIFICATE_PEM` and `PRIVATE_KEY_PEM`
as secrets. Automatic wildcard renewal is not part of this demo yet. Never
configure either public page's TLS private key here.

With Chrome installed, run against the two HTTPS pages of the empty deployment:

```sh
mise exec -- task js:keepalive:handoff SITE=https://... START=https://...
```

The check starts A from the start page, transfers the site A → B → C, then
checks the `503` and starts the site again. It doesn't deploy anything.

## where to look

- [`src/proxy.ts`](src/proxy.ts): fetch and check site files.
- [`src/peers.ts`](src/peers.ts): gossip, probes, and when to start another host.
- [`src/hosting/`](src/hosting/): copy the site, publish from a worker, and talk to peers.
- [`src/storage.ts`](src/storage.ts): save the complete copy and the earliest start time.
