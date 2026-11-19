# can we keep this alive?

Keepalive is a website served by browser tabs. One tab starts with a copy
from `start.keepthisalive.com`. Other tabs can volunteer: they copy the site
from a running host and start serving it through tnl. If the last host stops,
`keepthisalive.com` goes down. The startup site stays online.

## start here

| Follow                          | Open                                                                                                                                                      |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A visit**                     | [Edge entry point](src/edge/worker.ts) → [proxy](src/edge/proxy.ts) → [file serving in the host tab](src/hosting/serving.ts)                              |
| **A new host**                  | [Page](src/page/app.tsx) → [wait, copy, and verify](src/hosting/tab.ts) → [browser worker](src/hosting/worker.ts) → [tnl publish](src/hosting/publish.ts) |
| **Hosts talking to each other** | [Peer HTTP](src/peers/http.ts) handles invitations and heartbeats; [gossip](src/peers/gossip.ts) tracks recent hosts and decides when to recruit.         |

`src/page/` runs on the browser's main thread, `src/hosting/worker.ts` runs
in a dedicated worker in a host tab, and `src/edge/` runs on Cloudflare.
They share the [release manifest](src/release.ts) and [turn rules](src/policy.ts).

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

The edge proxy checks file sizes and hashes against the release manifest.
If it can't get a valid copy, it returns an empty `503` that browsers and
caches must not store.

The proxy discovers host addresses from the same bounded replies browsers
use. Each Cloudflare Worker instance rotates through the individual addresses
it knows and refreshes them in the background on incoming requests. It tries
up to three different addresses. The shared address is for initial discovery
and recovery, not file requests, so reusing one connection to the shared
address doesn't pin those requests to one browser. Each Worker sees only a
sample of the hosts; request distribution is not globally coordinated.

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
total. It replies with its current estimate of tabs and live hosts, the
experiment start time, and up to three other host addresses. Counts are
approximate, especially when a tab changes counting hosts.
Each host allows one pending start at a time. Simultaneous invitations can
still take them above the target: it is not a global admission limit.

An ordinary turn lasts up to ten minutes. A bootstrap turn lasts up to an
hour. With about two minutes left, a host looks for a replacement if the
pool needs it, and stops at zero even if nobody takes over. To hand off
early, it checks that the replacement answers at its own address. The proxy
won't approve a volunteer with the same public IP as the host inviting it.

The page shows the time since the first host started. Under **hosts**,
a small tree connects each tab to the host it copied from. The page fetches
up to 64 reports when you open the tree, not on every heartbeat. The tree
shows recent reports, not a complete history.

While hosting, the page shows successful file responses from this tab and
its share of the estimated tab count. The two numbers measure different
things: a tab's presence is counted by one host, but its file requests can
reach another.

The **stop** button ends a turn without waiting for a successor. When a
background volunteer is picked, the tab can play a short chirp. While
hosting, the page asks the browser to keep the visible screen awake and to
warn before closing. These are browser-dependent; a tab can still be
suspended or closed.

For the first host, `start.keepthisalive.com` supplies a permanent copy.
When you click **start hosting**, the page checks whether a host answers
through the proxy. If one does, the page sends you to the main site to
volunteer. If none answers, it lets you start an hour-long bootstrap turn.
A network error or two simultaneous starts can produce extra bootstrap
hosts. The startup page stays available when no hosts remain; the main site
never falls back to its copy.

## checking other hosts

[`tnl.config.ts`](tnl.config.ts) gives the `production` service one shared
address and each host its own address under `hosts.keepthisalive.com`. The
proxy can use any host. When A checks B, it needs B's address so that B is
the one that answers.

[`src/peers/gossip.ts`](src/peers/gossip.ts) holds each host's view of the others. Every few
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
counting B. An old mention from another host doesn't clear that suspicion;
a direct reply or a report B sent after the grace period can. A host doesn't
have to talk directly to every other host to count them.

Each reply includes the sender's report and up to 24 others. Recently
learned hosts, stops, and other status changes get some of that space; the
reply also includes fresh changes and rotates through older records. Reports
carry the sender's Unix time in milliseconds so forwarding an old report
doesn't make it new. A known host can count until its turn ends if no
probe has failed, but a tab count older than a minute doesn't count toward
the total. That can undercount tabs in a large group.

Each browser can hold 8,192 peer records, including stopped hosts. It reclaims
expired records before rejecting new ones and marks its counts as incomplete
if it has to drop reports.

[`src/peers/http.ts`](src/peers/http.ts) handles these requests
and the waiting invitations.

## reconnecting two groups

Suppose A knows B, and C knows D. Every 30 seconds or so, each
[hosting worker](src/hosting/worker.ts) asks the proxy for
`/__keepalive/peers`. Here, the Worker knows C's individual address:

```text
A knows B               proxy                                 C knows D
    |-- GET peers ------->|                                       |
    |                     |-- GET peers at C's address ---------->|
    |                     |<-- C and D ---------------------------|
    |<-- C and D ---------|                                       |
    |                                                             |
    |-- send A and B to C's own address ------------------------->|
    |<-- C's reply -----------------------------------------------------------|
```

A can now tell B about C and D; C can tell D about A and B. The proxy's
short-lived list can contain only hosts A already knows, so reconnecting
depends on eventually reaching the other group.

## when the clock resets

Running hosts pass the start time to new hosts. If A hands off to B and A
stops, B keeps the clock going. If everyone stops, the next host starts the
clock over.

The clock shows time since the shared start, not independently measured
uptime.

## carrying the service certificate forward

The bootstrap host asks tnl for a managed certificate for
`*.hosts.keepthisalive.com`. The scope covers the shared address and individual
publisher aliases, not the main site or startup site. It does not create a
wildcard DNS record.

After the upload check, an invited tab can fetch the inviter's installed
certificate and private key over HTTPS using the invitation. These are not
part of the site files or stored on the edge. A new host can reuse that
certificate if it has time left for the turn, startup, and clock differences.
In the last 24 hours of validity, each new host instead tries managed issuance
with probability one divided by the number of hosts its inviter knows.

Gossip carries only the installed certificate's fingerprint and expiry. A host
using an inherited certificate can ask a peer for a newer one and must answer
a one-time challenge at its own publisher alias. tnl checks the replacement
before installing it. The shared key is exposed to browsers that host; stopping
a tab does not revoke material it already copied. Use a dedicated subtree and
do not share this certificate with other services.

## checking the page

After `task js:keepalive:build`, run `mise exec -- node demos/keepalive/tests/preview.ts`
from the repository root with Chrome installed. It captures the built page
in `dist/screenshots/ui/` with simulated peers and hosting worker messages.
`task js:keepalive:handoff` instead uses an empty test deployment, checks
that successive service runs advertise the bootstrap certificate after the
previous host stops, and waits for a real volunteer turn to reach its
replacement window.

To model membership at 5,000 hosts, run the deterministic simulation:

```sh
mise exec -- node --max-old-space-size=8192 demos/keepalive/tests/membership-simulation.ts
```

It reports sampled membership and tab-count estimates, report age, and
certificate fingerprint propagation during churn, split groups, and suspended
hosts. It does not open network connections, launch browsers, or issue
certificates. Pass `--hosts 500` for a smaller run or `--proxy-sample` to add
a periodic discovery request to a proxy that knows fewer than 2% of aliases.
