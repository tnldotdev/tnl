# run a split tnl server on Fly

This is an example of running a tnl server as four Fly apps: control, ingress,
and two relay services. The manifests in this directory give each role its own
app and run the same selected server image across the roles.

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

## use this example

The Fly manifests describe each role; `process-counts.json` records the
desired Machine counts and relay groups. The deployment creates missing Fly
apps, public addresses, and Machines, then updates them to the selected image.
Supply PostgreSQL, DNS, and credentials separately. Migrate control's database
before updating the processes, keeping schema changes compatible with processes
still serving traffic. After deploying, check control readiness and make a new
publish run and visitor request; readiness alone does not test the full path.

For a self-hosted setup, start with the [self-hosting guide](https://tnl.dev/docs/self-hosting).
It covers PostgreSQL, DNS, TLS, and the standalone and split-role Compose
examples. This Fly topology is one way to run split roles.
