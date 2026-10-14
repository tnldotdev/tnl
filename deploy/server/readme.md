# deploy the tnl server

Use an isolated staging server to try changes before they reach production.
This repository runs the same split topology in each environment: control,
ingress, and two relay services. Each environment has its own PostgreSQL state,
hostnames, and credentials. Its roles run the same selected server image.

```text
publisher --> relay a
          --> relay b
visitor --> ingress --> relay a or b --> publisher --> local service

ingress + relays --> control --> PostgreSQL
```

Control keeps server state in PostgreSQL and coordinates ingress and relays.
Ingress accepts visitor connections and forwards them to a connected relay.
The two relay services provide separate places for a publisher to connect, so
one relay service can remain available while the other recovers. Ingress and
relays do not store server state. A small self-hosted server can instead start
with the standalone role and move to separate processes when it needs
independent failure boundaries.

## staging and production

Checks run in parallel on each change. A checked merge to `main` deploys a
commit-specific image to staging. Publishing a signed release, including an
RC, deploys that release image to production. The deployment first migrates
control's database, then updates the server processes. Schema changes must
remain compatible with processes that are still serving traffic during the
update.

To try a tnl branch or full commit SHA on the existing staging Machines before
merging it, dispatch the manual workflow from tnl main:

```sh
gh workflow run deploy-staging-source.yml --ref main -f tnl_ref=BRANCH_OR_SHA
```

It resolves the ref to one commit, builds and pushes one image to GHCR, and
uses its digest for migration and every Machine update. Before migration, it
requires the configured Machine count, distinct process identities, and
passing checks on all existing staging Machines; it prints previous image
references for rollback. It does not create or restart missing Machines.
The automatic main deployment still provisions missing apps and Machines.

The Fly manifests describe each role; `process-counts.json` records the
desired process counts and relay groups for each environment. The deployment
can create missing Fly apps and Machines, or update an existing set, without
changing the other environment. PostgreSQL, DNS, and credentials are supplied
separately. After a deployment, check control readiness and make a new publish
run and visitor request; readiness alone does not test the full path.

## qualify staging tcp ports

Staging ingress declares 3306/tcp, 5432/tcp and 10000-10031/tcp alongside
443/tcp on the same listener, with PROXY v2 on each port. The deployment checks
that both ingress Machines advertise exactly these ports in `ingress-a` with
PROXY v2. Production ingress still advertises only 443/tcp. The staging range
is a trial inventory, not a measured Fly port limit.

Keep `TNLD_TCP_PORTS` unset on staging control until both Machines advertise
the ports and an external visitor probe confirms that PROXY v2 contains the
original destination port at the ingress listener. A TCP connection alone
does not show that Fly forwarded the port to ingress. After qualifying each
port, run `mise exec -- task server:ingress:ports:staging`, then set
`TNLD_TCP_PORTS=3306,5432,10000-10031` on staging control and deploy,
publish a disposable database public URL and connect with a TLS-required
PostgreSQL or MySQL client. Check that HTTPS on 443 still works and inspect
`tnl_control_tcp_port_pool_ports{pool="ingress-a",state="configured"}` before
expanding the range or proposing production ports. Remove the test public URL
to let its port enter quarantine.

For a self-hosted setup, start with the [self-hosting guide](https://tnl.dev/docs/self-hosting).
It covers PostgreSQL, DNS, TLS, and the standalone and split-role Compose
examples. The topology here is one way to run split roles, not a requirement
for every server.
