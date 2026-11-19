# can we keep this alive?

Keepalive is a website served by browser tabs through tnl. Visitors volunteer
to copy the site from another host and take a turn serving it. If the last
host stops, `keepthisalive.com` goes down.

`start.keepthisalive.com` stays online to start the first host again. The main
site never falls back to that copy.

## how it works

```text
visitor                 Cloudflare proxy                 browser host
   |-- GET /app.js ----------->|                               |
   |                          |-- fetch through tnl --------->|
   |                          |<-- app.js --------------------|
   |                          | check size and hash           |
   |<-- checked app.js --------|                               |
```

The proxy rotates requests through known browser hosts and checks each file
against the release manifest. If it can't get a valid copy, it returns `503`.

Hosts exchange reports and invite waiting volunteers when more copies are
needed. A volunteer copies the files, can inherit the service certificate,
and serves from memory for up to ten minutes. The first host gets up to an
hour. Counts and peer lists are approximate.

## read the code

- [Proxy](src/edge/proxy.ts): find a host, fetch files, and verify them.
- [Hosting](src/hosting/worker.ts): publish the copy and manage the turn.
- [Peers](src/peers/gossip.ts): share reports and decide when to recruit.
- [Page](src/page/app.tsx): volunteer, show progress, and stop hosting.
- [Configuration](tnl.config.ts): the shared service and publisher addresses.

## checks

From the repository root:

```sh
mise exec -- task js:keepalive:test
```

`task js:keepalive:handoff` uses Chrome and an empty test deployment to check
browser handoffs, certificate reuse, final-host outage, and restart.
