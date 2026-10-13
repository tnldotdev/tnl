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

The Fly manifests describe each role; `process-counts.json` records the
desired process counts and relay groups for each environment. The deployment
can create missing Fly apps and Machines, or update an existing set, without
changing the other environment. PostgreSQL, DNS, and credentials are supplied
separately. After a deployment, check control readiness and make a new publish
run and visitor request; readiness alone does not test the full path.

For a self-hosted setup, start with the [self-hosting guide](https://tnl.dev/docs/self-hosting).
It covers PostgreSQL, DNS, TLS, and the standalone and split-role Compose
examples. The topology here is one way to run split roles, not a requirement
for every server.
