# can we keep this alive?

[Keepalive](https://keepthisalive.com) is a website hosted by its visitors'
browser tabs. Each host copies the site from another host and serves it through
tnl. If the last host leaves, the site goes down.

## take a turn

Open [keepthisalive.com](https://keepthisalive.com) and click **i'll keep it alive**.
Your tab waits until a host invites it, then copies the files and starts serving.
No install needed.

A turn lasts up to 15 minutes, starting when your tab is ready to serve.
Keep the tab open while you're hosting. You can stop anytime.

The hosts gossip to keep track of each other and decide when to invite more
volunteers. The “alive for” counter keeps going as they pass the site along.

If nobody is hosting, [start.keepthisalive.com](https://start.keepthisalive.com)
can start the first host again, for up to an hour. The counter starts over.
The main site never falls back to that seed copy.

## how it works

A Cloudflare Worker fetches each file from a hosting tab through tnl and checks
its size and SHA-256. If it can't get a valid copy, it returns an empty `503`.

When a volunteer copies the hosting code, its donor can send the large WASM
file compressed. The volunteer checks the size and SHA-256 of the uncompressed
bytes before running it.

An already-open tab stays on screen. If the Worker finds no reachable host,
the clock resets and volunteering stops. A missed check alone doesn't reset
the clock. The tab picks up a new host without reloading.

[Read the post and try the interactive diagrams](https://tnl.dev/blog/keepalive).

## read the code

- [Gossip](src/peers/gossip.ts): exchange reports and decide when to recruit.
- [Hosting](src/hosting/tab.ts): copy the site and start the hosting worker.
- [Proxy](src/edge/proxy.ts): find a host and check the files it sends.
- [Checks](tests/readme.md): run the tests and measure handoffs.
- [Operations](operations.md): production and ramp hostnames, Worker credentials, and the browser restart check.
