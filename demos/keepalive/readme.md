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

## scale qualification

The qualification target is 1,000 simultaneous browser hosts, not 1,000 lifetime
enrollments. Set the Worker's `HOST_TARGET` to the fixed pool size for an opt-in
run; ordinary demand-driven recruitment still starts at three.

The admission Durable Object permits at most 384 startups and 1,384 total
reservations, including bundle transfers and replacement overlap above the
1,000-host target. This covers roughly 334 simultaneous replacements at the
three-minute startup bound. Retries
reuse their reservation; failed starts and lost tabs expire. Successful cleanup
releases the reservation only after the publisher closes. It stores no site
assets and does not serve as a backup.

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
