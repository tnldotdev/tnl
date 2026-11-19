# can we keep this alive?

Keepalive is a website served by browser tabs. Tabs copy the site from each
other and serve it through tnl. If every host stops, the site goes down.

## serving the site

```text
visitor                 Cloudflare proxy                 host A
   |                           |                            |
   |-- GET /app.js ----------->|                            |
   |                           |-- fetch through tnl ------>|
   |                           |<-- app.js -----------------|
   |                           | check size and hash        |
   |<-- checked app.js --------|                            |
```

[`src/worker.ts`](src/worker.ts) handles requests to `keepthisalive.com`.
[`src/proxy.ts`](src/proxy.ts) fetches files from a browser host and checks
their sizes and hashes against the release manifest. If it can't get a valid
copy, it returns an empty `503` that browsers and caches must not store.

## adding a host

A visitor can volunteer their tab. It waits with an existing host until that
host asks it to help:

```text
host A                              volunteer B
   |                                      |
   |<-- wait for an invitation -----------|
   |-- "start" -------------------------->|
   |<-- upload check ---------------------|
   |<-- download the site ----------------|
   |-- files ---------------------------->|
   |<-- I'm hosting too ------------------|
```

[`src/hosting/tab.ts`](src/hosting/tab.ts) checks the downloaded files and
hands them to a Web Worker. The worker serves them from memory through tnl.
Before B publishes, it uploads 1 MiB to A within three seconds, with one
retry. This is a screen for the connection between them, not a guarantee of
serving performance. The bootstrap browser skips the check. The invitation
tells B when to try; tnl grants permission to publish.

Hosts aim for one running copy per 50 live tabs, rounded up, with a floor of
three. Tabs send a short heartbeat to one host every 20 seconds. That host
expires silent tabs after a minute and gossips its own count, not a global
total. Counts are approximate, especially when a tab changes counting hosts.
Each host allows one pending start at a time. Simultaneous invitations can
still take them above the target: it is not a global admission limit.

An ordinary turn lasts up to ten minutes. A bootstrap turn lasts up to an
hour. With about two minutes left, a host looks for a replacement if the
pool needs it, and stops at zero even if nobody takes over. To hand off
early, it checks that the replacement answers at its own address. The proxy
won't approve a volunteer with the same public IP as the host inviting it.

The page shows recently observed hosts by name. Its handoff history
distinguishes sharing a verified copy from replacing a departing host.

For the first host, `start.keepthisalive.com` supplies a permanent copy.
That page stays available when no hosts remain. The main site never falls
back to that copy.

## checking other hosts

[`tnl.config.ts`](tnl.config.ts) gives the `production` service one shared
address and each host its own address under `hosts.keepthisalive.com`. The
proxy can use any host. When A checks B, it needs B's address so that B is
the one that answers.

[`src/peers.ts`](src/peers.ts) holds each host's view of the others. Every few
seconds, a host checks one peer and exchanges reports about who it knows.
Passing those reports along is the gossip.

If B doesn't answer A, A asks C to check:

```text
host A                    host C                    host B
   |-- check B ---------------------------------------->|
   |                     no reply                       |
   |-- check B ------------->|                          |
   |                         |-- check B -------------->|
   |                         |<-- B's reply ------------|
   |<-- B's reply -----------|                          |
```

If both checks fail, A gives B a 15-second grace period before it stops
counting B. Hearing another host mention B doesn't count as a reply from B.
[`src/hosting/peer-http.ts`](src/hosting/peer-http.ts) handles these requests
and the waiting invitations.

## reconnecting two groups

Suppose A knows B, and C knows D. Every 30 seconds or so, each
[hosting worker](src/hosting/worker.ts) asks the proxy for
`/__keepalive/peers`. Here, tnl sends the request to C:

```text
A knows B               proxy         prod.hosts.keepthisalive.com        C knows D
    |-- GET peers ------->|                         |                         |
    |                     |-- GET peers ----------->|                         |
    |                     |                         |-- GET peers ----------->|
    |                     |                         |<-- C and D -------------|
    |                     |<-- C and D -------------|                         |
    |<-- C and D ---------|                         |                         |
    |                                                                         |
    |-- send A and B to C's own address ------------------------------------->|
    |<-- C's reply -----------------------------------------------------------|
```

A can now tell B about C and D; C can tell D about A and B. The proxy keeps no
host list. A request can reach a host A already knows, so reconnecting depends
on eventually reaching the other group.

## when the clock resets

Running hosts pass the start time to new hosts. If A hands off to B and A
stops, B keeps the clock going. If everyone stops, the next host starts the
clock over.
