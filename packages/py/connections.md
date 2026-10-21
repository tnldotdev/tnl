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
or signs in. Without a prepared owner, await the handle first. Python runs
bounded native CLI subprocesses for reads; it does not run nested event loops
or implement the connection transport. Awaited operations run those same calls
in a worker thread.

The SDK uses the platform wheel's existing native binary resolver, then these
schema-1 commands:

```text
tnl --no-telemetry runtime connections start --directory DIR --parent-pid PID --service NAME
tnl --no-telemetry runtime connections read --handle FILE --service NAME
tnl --no-telemetry runtime connections stop --handle FILE
```

Startup returns `private_handle`, `executable`, and `public_runtime`. The SDK
keeps the handle private and uses its selected wheel binary for later calls.
Native code owns handle-file permissions, configuration/credential binding,
authorization, listener setup, renewal, and cleanup. Python passes no secrets in
arguments and discards native diagnostic output rather than exposing provider
details. stdout is bounded to 128 KiB and each command to 65 seconds.

## lifecycle and expiry

Handles for the same canonical directory, service, and mounted handle share
one session within a Python process. Concurrent threads and awaiters coalesce
startup. Different services can have different owners. A failed startup is
shared until the handle is closed; it does not repeatedly trigger sign-in.

Call `handle.close()` or `await handle.aclose()` when finished. Closing affects
all handles sharing that SDK-owned session. A supplied owner is left running.
SDK-owned sessions also register cleanup after successful preparation, and the
native owner monitors the Python parent process. Canceling an await does not
kill a shared startup needed by other callers; it finishes in its worker thread
and retains those same cleanup boundaries. Imports perform no discovery,
authentication, process startup, or environment mutation.

Snapshots have `expires_at`. Read another snapshot before opening a new client
connection; expired material fails closed. The SDK does not mutate existing
driver settings or refresh an existing pool. Drain and recreate pools with a
fresh snapshot before expiry. If the native session itself expired or was
revoked, close its handle and explicitly prepare a new one.

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
  `sslmode="verify-full"`. libpq does not accept a Python `SSLContext`. When
  `db.ca` is present, supply its PEM through a caller-owned private temporary
  `sslrootcert` file for the full lifetime of the connection or pool. When it is
  absent, use `sslrootcert="system"` on libpq versions supporting system roots,
  or an explicit trusted root file on older versions. Database/user/password
  remain the application's settings.
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
