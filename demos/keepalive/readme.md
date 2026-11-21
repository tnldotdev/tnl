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
and serves from memory for up to 15 minutes. The first host gets up to an
hour. The countdown starts when serving starts. A soft chime sounds with five
minutes left unless you mute it; replacement can begin with four minutes left.

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

## scale qualification

Each host offers one invitation at a time. It aims for at least three hosts,
then roughly one per 50 observed visitor tabs. Peer counts are approximate.
Two browsers on the same network can hand off. If a volunteer disappears, the
invitation expires. The donor checks the replacement at its exact publisher
address before finishing a handoff. The Worker checks the donor's invitation
before requesting a one-use enrollment key. Returning identities can reuse
their existing grant.

For an existing coordinator-backed deployment, stop new turns on the old
release and let active turns drain (including the one-hour first host) before
applying the Worker migration that retires its old reservations.

Volunteer selection uses finite requests with 5–15 second retry jitter. Peer
responses request connection closure, including HTTP/2 GOAWAY, so random probes
and 20-second presence reports do not retain idle relay streams. Startup allows
three minutes; replacement begins four minutes before the turn ends.

Qualify 3, 10, 30, 100, 300, then 1,000 hosts. At each stage measure open visitor
connections, gossip bytes, startup time, bundle transfer and verification,
browser memory, relay load, and capacity rejections. Run multiple replacement
cycles, a volunteer surge, slow transfers, and loss of either relay service.
Count visitors separately from hosts. Configuration ceilings and simulations
are not proof of real-browser throughput.
