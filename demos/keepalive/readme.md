# can we keep this alive?

Keepalive is a website served by browser tabs. Open `start.keepthisalive.com`,
click **start hosting**, and leave the tab open. In another browser, open
`keepthisalive.com` and click **i'll keep it alive**. When more hosts are needed,
that tab gets a copy of the site and starts serving it too.

Close every hosting tab and `keepthisalive.com` returns `503`. The start page
still works: anyone can use it to start a host again.

## follow a request

```text
visitor            keepthisalive.com         browser host
  |                       |                       |
  |--- GET /app.js ------>|                       |
  |                       |--- GET /app.js ------>|
  |                       |       through tnl     |
  |                       |<--- app.js -----------|
  |                       | checks size and hash  |
  |<--- checked app.js ---|                       |
```

The Cloudflare proxy checks files against a fixed release manifest. It doesn't
fall back to the start page's copy. A tab that takes over downloads the whole
release from another host, including the code it needs to host and the
[Fira Code](https://github.com/tonsky/FiraCode) font.

## how hosts find each other

Say browser A knows browsers B and C. Every few seconds it picks a host to check.
If B doesn't answer, A asks C to check B:

```text
browser A             browser C             browser B
    |------------------ check B ---------------->|
    |                   no reply                 |
    |--- check B -------->|                      |
    |                     |--- check B --------->|
    |                     |<--- B's reply -------|
    |<--- B's reply ------|                      |
```

If neither check works, A gives B a 15-second grace period before it stops
counting B. Hosts pass along small batches of reports. Hearing _about_ a known
host doesn't reset the clock on its last reply. While A remembers B's
departure, a delayed report can't bring that run back. If B restarts at the
same address, a report from the old run can't overwrite the new one.

What if A and B know each other but neither knows C or D? About every 30 seconds,
each host asks for a peer report through the shared tnl URL,
`prod.hosts.keepthisalive.com`. If A's request reaches C, A learns C's address
and can check it directly. The two groups can then pass along what they know.
That lookup can land on a host A already knows; it isn't guaranteed to find a
new one. The proxy doesn't keep a host list.

When a host sees fewer than three hosts, including tabs it knows are starting,
it can invite a waiting tab. Each host keeps its own waiting list. Two hosts
can invite someone at the same time; three is a target, not a limit. Hosts also
share the earliest start time they remember. That's experiment age, not uptime.

## try it locally

Run these from the repository root:

```sh
mise exec -- task js:keepalive:preview  # Vite page, no tunnels
mise exec -- task js:keepalive:test    # gossip and file checks
```

To see what happens when no host is running, start the proxy with Wrangler:

```sh
mise exec -- task js:keepalive:dev \
  FLAGS='--var START_HOST:localhost --var SHARED_HOST:https://127.0.0.1:1'
```

Open `http://localhost:8787` for the start page. From another terminal, request
the main site path. With no hosts, this prints `503`:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8787/
```

## test a browser handoff

Use an empty test deployment named `keepalive` with a public, anonymous HTTP
service named `site`, multiple publishers enabled, and publisher addresses under
`hosts.keepthisalive.com`.

- Set `SITE_ORIGIN`, `START_HOST`, and `SHARED_HOST` to the test addresses.
- Set `PROJECT_KEY` and `TEAM_ID` for that deployment, and `CONTROL_URL` for its
  tnl server. Give the proxy a scoped `MANAGEMENT_TOKEN` secret to create one-use
  enrollment keys for `site`. Set enrollment rate limits before making the start
  page public.
- Use tnl-managed certificates if available. For the shared wildcard, set
  `CERTIFICATE_PEM` and `PRIVATE_KEY_PEM` as proxy secrets. Don't use either
  public page's TLS key. Automatic wildcard renewal isn't in the demo yet.

With Chrome installed, run:

```sh
mise exec -- task js:keepalive:handoff \
  SITE=https://keepalive-test.example.com START=https://start-test.example.com
```

The test starts A from the start page, transfers the site from A to B and then
from B to C, and checks that the last host can serve the site on its own. It
then stops that host, checks for `503`, and restarts the site. It doesn't deploy
anything.

## read the code

- [Proxy](src/proxy.ts): fetch and check files.
- [Peers](src/peers.ts): share reports, check hosts, and decide when to start another.
- [Hosting](src/hosting/): copy the site, publish it, and talk to other hosts.
- [Storage](src/storage.ts): save the site and the earliest known start time.
