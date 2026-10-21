# python connection boundary

`tnl.connect("database")` selects a project service. Await the handle to prepare
its native connection owner and read one snapshot:

```python
import tnl

handle = tnl.connect("database")
db = await handle
assert db.host == "127.0.0.1"
assert db.ssl.check_hostname
```

The result is an immutable, non-awaitable Python object. `db.ssl` is a Python
`ssl.SSLContext` with certificate verification and hostname checks enabled.
`db.server_hostname` is the managed service hostname, while `db.host` and
`db.port` select the actual native loopback listener. `db.ca` is optional PEM
trust data, not a path. Client certificates and private keys never enter Python.
HTTP snapshots also have `url`, the managed HTTPS origin, independent of the
loopback port. Kubernetes snapshots also have `kubeconfig` and `context` from
the native owner; use that kubeconfig's native credential plugin.
Opaque TCP snapshots have only `host`, `port`, `protocol`, and `expires_at`;
native code verifies and terminates their managed visitor TLS leg.

## prepared synchronous reads

An existing native owner can be supplied through the private
`TNL_CONNECTION_HANDLE` environment variable. Then properties and `snapshot()`
work synchronously, including from an active asyncio event loop:

```python
import tnl

handle = tnl.connect("database")
db = handle.snapshot()  # one coherent snapshot from the prepared owner
host, port = db.host, db.port
```

Each handle property reads current material. Use `snapshot()` when several
settings must come from the same read. Synchronous access never starts an owner
or contacts control. An unprepared sibling fails without opening its listener.
Without prepared settings, await the handle first. Python runs bounded native
CLI subprocesses for synchronous reads. Async preparation uses a reusable,
authenticated private IPC connection in a worker thread; native code owns the
service transport and authorization.

The SDK uses the platform wheel's existing native binary resolver, then these
schema-1 commands:

```text
tnl --no-telemetry runtime connections start --directory DIR --parent-pid PID
tnl --no-telemetry runtime connections read --handle FILE --service NAME
tnl --no-telemetry runtime connections stop --handle FILE
```

Startup returns `private_handle`, `executable`, and `public_runtime`. The SDK
keeps the handle private and uses its selected wheel binary for later calls.
Native code owns handle-file permissions, configuration/credential binding,
authorization, listener setup, renewal, and cleanup. Python passes no secrets in
arguments and discards native diagnostic output rather than exposing provider
details. stdout is bounded to 128 KiB and each command to 65 seconds.
The command deadline includes stdin backpressure, stdout reads, and process exit;
failed commands kill and reap their child. Private request input is also bounded
to 128 KiB. Canceling an async caller leaves its bounded worker to finish.

Each async workload call reacquires its source assertion. Only exact assertion
bytes with a control-confirmed binding and expiry may reuse identity selection.
Native-only Fly acquisition intentionally retains per-await native identity
selection because Python does not hold those assertion bytes. Synchronous reads
never acquire or attach assertions.

## lifecycle and expiry

Handles for the same canonical directory and mounted handle share
one human owner within a Python process. Workload handles share only after
control verifies the same immutable identity and policy. Services prepare
incrementally within that owner. Concurrent threads and awaiters coalesce
startup. A failed startup is
shared until the handle is closed; it does not repeatedly trigger sign-in.

Call `handle.close()` or `await handle.aclose()` when finished. Closing affects
all handles sharing that SDK-owned session. A supplied owner is left running.
SDK-owned sessions also register cleanup after successful preparation, and the
native owner monitors the Python parent process. Canceling an await does not
kill a shared startup needed by other callers; it finishes in its worker thread
and retains those same cleanup boundaries. Imports perform no discovery,
authentication, process startup, or environment mutation.

Sessions belong to the Python process that created them. After `fork()`, inherited
handles fail closed, inherited exit hooks cannot stop the parent's native owner,
and new handles use fresh locks and IPC. Create and await handles in each serving
worker. Inactive workload policy contexts are reclaimed when their sessions close
or identity selection fails; the 32-policy bound applies to active selections and
sessions rather than every manifest hash the process has seen.

Snapshots have `expires_at`. Read another snapshot before opening a new client
connection; expired material fails closed. Human owner lifetime follows the
application rather than a one-hour timer. Workload sessions keep their fixed
deadline and renewable lease separately. A fresh verified assertion can authorize
a replacement reusable-provider session for future accepts on the same listener.
An early native process death is recoverable only after native proves its OS
lifetime lock is released. A temporary IPC failure never permits a second owner.

Synchronous properties and `snapshot()` on a known-expired owned session raise
`sdk.connection_expired`; they never start a replacement. A shorter snapshot
expiry or a transient native read failure does not replace a live owner. Await
the handle explicitly when fresh preparation is needed.

Existing snapshots stay immutable. The SDK does not mutate driver settings or
refresh an existing pool. Drain and recreate database pools or connections with
newly awaited settings; tnl never replays SQL during owner replacement.
An owner supplied through `TNL_CONNECTION_HANDLE` remains caller-owned, including
fixed-deadline workload sessions. After its expiry the caller must prepare a new
owner and select its handle; the SDK does not stop or replace it. Revocation is
not permission to recover old access: any new preparation must pass current
native authorization.

## portable project types

Run `tnl generate`, then add the generated package to this project's environment:

```console
uv add --editable ./.tnl/generated/python
```

`tnl init` runs that command for a Python project; `tnl init --no-install` prints
it. The editable dependency wires both runtime imports and type-checker lookup
to the same project-local package. It neither replaces `tnl` nor installs a
global module. Commit `.tnl/generated/python/` and the project dependency/lock
changes. Regenerate after changing declared services. `tnl generate --check`
also checks the Python artifacts without writing them.

```python
from typing import Literal, assert_type
from tnl_project import tnl

handle = tnl.connect("database")
db = await handle
assert_type(db.protocol, Literal["postgres"])
# tnl.connect("unknown") is a type error for a static project configuration.
```

Static YAML/JSON configurations emit exact `Literal` names and protocol-specific
snapshot types. Runtime checks reject unknown names and protocol drift from a
stale facade. An empty static configuration accepts no service name. Generated
files contain service names and protocol types, never endpoints, trust data,
credentials, or checkout paths.

TypeScript configs, including factories, currently emit an explicitly generic
Python facade. Their evaluated names and protocols are not proof of a stable
cross-worktree declaration. Generic calls validate names in the native runtime
and return the `Connection` union; narrow it with `isinstance` or `protocol`.
The TypeScript declaration file continues to reference the source config type,
preserving its optional services and protocol unions. Python does not convert
one evaluated factory result into universally exact types.

## client adapters

For opaque TCP services, connect to the native loopback listener:

```python
import socket

with socket.create_connection((stream.host, stream.port), timeout=10) as raw:
    raw.sendall(b"hello")
```

PostgreSQL and MySQL negotiate TLS inside their database protocol. Do not wrap
their raw socket as direct TLS. These snapshots are deliberately not arbitrary
`**kwargs` for every database library:

- psycopg/libpq can separate the dial address from the verified hostname. Use
  `host=db.server_hostname`, `hostaddr=db.host`, `port=db.port`, and
  `sslmode="verify-full"`, `channel_binding="disable"`, and
  `gssencmode="disable"`. libpq does not accept a Python `SSLContext`. When
  `db.ca` is present, supply its PEM through a caller-owned private temporary
  `sslrootcert` file for the full lifetime of the connection or pool. When it is
  absent, use `sslrootcert="system"` on libpq versions supporting system roots,
  or an explicit trusted root file on older versions. Database/user/password
  remain the application's settings.
  PostgreSQL SCRAM channel binding cannot cross the publisher's separate TLS
  connections; disabling it retains certificate and hostname verification.
  `gssencmode="disable"` selects PostgreSQL TLS negotiation rather than GSS
  encryption. This API does not disable either option on the application's behalf.
- PyMySQL accepts an `SSLContext` but uses its dial `host` for TLS hostname
  verification. Passing `host=db.host` would verify `127.0.0.1`, not the managed
  hostname. This API does not provide a drop-in PyMySQL/mysqlclient adapter;
  choose a driver with an independently configurable TLS server name or supply
  a reviewed driver adapter. `ssl_verify_identity=False` and disabling context
  checks are not supported workarounds.
- An HTTP URL alone does not configure a Python HTTP client's native loopback
  dial address or private request authorization. Use a client adapter that
  preserves the managed origin/SNI and the native owner's admission boundary;
  this SDK does not install a global resolver or an httpx transport.

## checks

`mise exec -- task py:check` runs the routine lifecycle, process bounds, expiry,
and validation coverage. The project-metadata Go tests run strict mypy against
generated facades, checking exact protocols, invalid literals, and non-awaitable
results. They also retain the TypeScript union/optional-service compiler proof.

For the real Go owner/CLI and hostname-verified Python TLS proof, build the two
binaries into a private temporary directory, then pass their paths:

```console
GOMAXPROCS=2 GOFLAGS=-p=2 mise exec -- go build -o /private/tmp/tnl-python-proof/tnl ./cmd/tnl
GOMAXPROCS=2 GOFLAGS=-p=2 mise exec -- go build -o /private/tmp/tnl-python-proof/owner ./packages/py/tests/testdata/connection_owner
mise exec -- uv run --frozen --project packages/py pytest -q packages/py/tests/test_connections_native.py --tnl-binary /private/tmp/tnl-python-proof/tnl --tnl-connection-owner /private/tmp/tnl-python-proof/owner
```

This local fixture uses the real native IPC owner and native CLI read operation,
an ephemeral certificate, PostgreSQL SSLRequest negotiation, and a real TLS
socket. It checks failed hostname verification, opaque TCP settings, and unsafe
handle permissions without contacting a deployed server.

When psycopg is already installed in the test environment, the optional
`test_installed_psycopg_uses_verified_hostname_and_explicit_transport_options`
also uses actual libpq, the real native prepared-read operation, and the fixture's
PostgreSQL password/TLS handshake. It checks the managed hostname with a loopback
dial address, verified trust, the explicit options above, and rejection of an
incorrect hostname or required channel binding. It does not qualify SQL, SCRAM
authentication through a publisher, pooling, or other Python database drivers.
The locked SDK test dependencies do not install psycopg; the test reports a skip
when it is absent.
Local qualification used Python 3.13.9, psycopg 3.2.9's binary implementation,
and libpq 17.5 on macOS arm64.

For configured-app metadata and Uvicorn registration, run:

```console
mise exec -- task py:test -- -k 'app_metadata or worker_registers'
```

The Go app fixture builds assignments with `projectmeta.NewEndpoint` and
`Metadata.Public(true)`. Python validates HTTP, TCP, PostgreSQL, MySQL, and
Kubernetes siblings, including their allocated ports and public/private exposure.
Only the selected Uvicorn app must be HTTP; its `public_url` retains the native
HTTPS origin and port even when its managed endpoint is private.

The native subprocess checks use the real local publisher handler, scoped
capability, and SQLite-backed registration manager for prepare, register, renew,
and unregister. The publication worker is a fixture; these checks do not exercise
control allocation, CLI owner discovery, certificates, relays, or visitor traffic.
Separate real Uvicorn worker/reload checks use native-produced assignments through
a Python HTTP fixture to verify listener binding and shutdown order.
