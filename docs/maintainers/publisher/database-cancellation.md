# native database cancellation

native PostgreSQL `CancelRequest` is unsupported on managed `protocol: postgres`
services. the publisher rejects plaintext cancellation before TLS and rejects
TLS-wrapped cancellation before forwarding its startup packet to the provider.
an admitted second connection does not prove ownership of the original backend
PID/key. TLS and successful SQL queries alone do not qualify native cancellation.

## supported query bounds

use PostgreSQL's `statement_timeout` to bound work at the provider. a driver's
local timeout or closing its socket does not prove the provider stopped a query.
set the timeout before starting work, or set a transaction-local timeout:

```sql
begin;
set local statement_timeout = '5s';
select pg_sleep(60);
-- after SQLSTATE 57014, roll back the failed transaction.
```

when the database role permits it, a separate authenticated SQL connection can
call `select pg_cancel_backend($1)` with the intended backend PID. PostgreSQL owns
that permission check; it is separate from tnl's visitor authorization. the
installed `pg` fixture checks that this interrupts the intended `pg_sleep`, another
sleeping connection finishes, the original session remains usable, and the query
is not replayed. tnl does not automatically translate driver cancellation into SQL.

retain verified TLS and the service name:

- `pg`: use the returned native `host`, `port`, and `ssl` settings; leave
  `enableChannelBinding` disabled. `Client.cancel()` sends a plaintext second
  connection even when the original client uses TLS.
- Postgres.js: use returned native settings with ordinary SQL account options.
  its `query.cancel()` negotiates TLS but still carries an unbound PID/key; the
  publisher refuses it.
- psql/libpq: use `sslmode=verify-full`, the managed hostname, and
  `channel_binding=disable`. libpq 17 cancellation uses a plaintext second socket.
- psycopg: use `host=settings.server_hostname`, `hostaddr=settings.host`,
  `port=settings.port`, `sslmode="verify-full"`, a trusted `sslrootcert`, and
  `channel_binding="disable"`. the isolated installed fixture uses psycopg 3.2.10
  with libpq 17.5 and proves a wrong TLS name fails. psycopg is a test-consumer
  dependency, not a tnl runtime dependency.

visitor and target TLS have different channel bindings. SCRAM-PLUS still fails
closed with SQLSTATE `0A000`; these cancellation changes do not hide the target's
PLUS offer or weaken certificate/name checks. PostgreSQL SSLRequest and the
GSS-refusal-then-SSLRequest exchange remain supported.

## regression proof

```console
GOMAXPROCS=2 GOFLAGS=-p=2 mise exec -- task go:test:database-native -- -race
GOMAXPROCS=2 GOFLAGS=-p=2 mise exec -- task go:test:integration:tcp-clients
```

the second Task creates and removes digest-pinned TLS PostgreSQL and MySQL. the
installed Node consumer uses packed SDK/native packages; the Python consumer
installs a wheel containing the real native executable into an isolated uv
environment. both read the real connection owner's prepared IPC. their sockets
pass through trusted PROXY v2 metadata, the real public service ingress, the
in-process relay-forwarder fixture, `ServiceStream`'s PostgreSQL negotiation and
authentication bridge, then independently verified provider TLS. authority and
placement decisions are fixtures; this is not a deployed relay or control test.

`TestIntegrationManagedPostgresCancelOwnership` starts a real `pg_sleep(10)` and
waits for `pg_stat_activity.wait_event = 'PgSleep'` before sending each negative
probe. before the fix, an independently admitted client certificate on the same
service, or the same client on a sibling service sharing the provider, could use
the first session's key to interrupt it with `57014: ... user request`. plaintext
already failed closed. the regression now requires only `statement_timeout` to
end those queries. backend PID and a nontransactional sequence prove the original
session survives with one execution; an independent connection remains usable.
the manually constructed packets are negative ownership probes, not proof of
supported native cancellation.

the installed `pg`, Postgres.js and psycopg consumers also call their real native
cancellation APIs against sleeping SQL. they require the same timeout result,
one sequence increment, and the same backend session. `pg` and Postgres.js cover
ESM and CommonJS. `pg`, Postgres.js and mysql2 cover original connector decision
expiry versus same-session decision renewal. the direct PostgreSQL lifetime
test rechecks the original TLS leaf after a replacement credential opens another
connection: the replacement cannot extend the original authorization deadline;
renewing the original subject retains its PID and temporary table.

## follow-up: authenticated cancellation ownership

restoring native cancellation needs a separate design. `ServiceVisitorDecision`
currently exposes only allowance and a deadline, not a stable subject/service
binding for the backend key. a safe design must:

- bind or replace BackendKeyData with an unguessable cancellation capability scoped
  to the original visitor subject, service, publish run and physical backend
  session; never use PID alone;
- authenticate the second connection and recheck that exact subject's current
  permission and original credential/session bounds before touching the backend;
- define lookup, expiration and cleanup across publisher replicas, restarts,
  disconnected sessions and backend PID reuse, with no query or cancel replay;
- qualify ordinary clients' actual second-socket TLS behavior, including any newer
  libpq encrypted-cancellation options, while retaining SSLRequest/GSS and the
  existing SCRAM-PLUS boundary.

upgrading libpq alone does not supply the missing ownership binding. accepting a
legacy plaintext CancelRequest is not an acceptable compatibility fix. retain the
explicit unsupported result until ordinary-client tests prove authenticated
cancellation of only the intended query across these boundaries.
