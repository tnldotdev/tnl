# python connections

Use `tnl.connect` from your project directory to reach a declared service.
Start the service's publisher and run `tnl auth login` with an identity that can
visit it. See the [AWS publisher guide](https://tnl.dev/docs/aws-publishers)
for one way to run a publisher beside your database. The SDK uses the native tnl
binary included in its platform wheel.

## postgres with psycopg

Add Psycopg with `uv add "psycopg[binary]"`. For a PostgreSQL service named `database`:

```python
import asyncio
import os
from tempfile import NamedTemporaryFile

import psycopg
import tnl
from tnl import PostgresConnection


async def main():
    handle = tnl.connect("database")
    try:
        db = await handle
        assert isinstance(db, PostgresConnection)
        with NamedTemporaryFile(mode="w+") as roots:
            if db.ca:
                roots.write(db.ca)
                roots.flush()
            async with await psycopg.AsyncConnection.connect(
                host=db.server_hostname,
                hostaddr=db.host,
                port=db.port,
                sslmode="verify-full",
                sslrootcert=roots.name if db.ca else "system",
                channel_binding="disable",
                gssencmode="disable",
                user=os.environ["DB_USER"],
                password=os.environ["DB_PASSWORD"],
                dbname=os.environ["DB_NAME"],
            ) as connection:
                await connection.execute("select 1")
    finally:
        await handle.aclose()


asyncio.run(main())
```

`hostaddr` dials the local connector; `host` names the service whose certificate
libpq must verify. Keep the temporary CA file open for the connection or pool's
lifetime. `sslrootcert="system"` requires a libpq version with system-root
support; on older versions, supply a trusted root file instead.

PostgreSQL negotiates TLS inside its protocol. Keep the explicit channel-binding
and GSS settings above: channel binding cannot cross the publisher's separate
TLS connections, and `gssencmode="disable"` selects TLS negotiation.
tnl access is separate from your database username and password.

## other clients

Inside an async function, a `tcp` service works with an ordinary socket:

```python
import socket
import tnl
from tnl import TCPConnection

handle = tnl.connect("ssh")
try:
    stream = await handle
    assert isinstance(stream, TCPConnection)
    with socket.create_connection((stream.host, stream.port), timeout=10) as connection:
        banner = connection.recv(256)
finally:
    await handle.aclose()
```

- **Kubernetes:** Use the returned `kubeconfig` and `context`, including the
  kubeconfig's native credential plugin.
- **MySQL:** Settings include a verified `ssl.SSLContext`, but there is no
  drop-in PyMySQL/mysqlclient adapter. A driver must dial `host` while verifying
  `server_hostname`. Passing the loopback address as the TLS name fails verification.
- **HTTP:** There is no bundled HTTPX transport. An adapter must dial the local
  connector while preserving the managed origin, TLS name, and request
  authorization. Passing the returned `url` to an ordinary HTTP client is insufficient.

## keep connections current

Await a handle before opening a client. Returned settings are snapshots; await
again for fresh settings when replacing a connection or pool. tnl does not update
an existing pool or replay failed queries.

After preparation, `handle.snapshot()` reads settings synchronously. It also
works with a prepared `TNL_CONNECTION_HANDLE`; it cannot start a connector or
sign in. Create handles inside each serving worker after a fork.

Close clients before calling `handle.close()` or `await handle.aclose()`.
Closing stops the SDK-owned connector shared by related handles. A connector
supplied through `TNL_CONNECTION_HANDLE` remains the caller's responsibility.

## typed service names

```console
tnl generate
uv add --editable ./.tnl/generated/python
```

Keep the normal `import tnl` and import the generated immutable `services` snapshot
separately. With `database` declared as `postgres`, the normal client's literal
service name infers `PostgresConnection`:

```python
from typing import assert_type

import tnl
from tnl_project import services


async def use_database(
    environment: tnl.EnvironmentReference,
    identity: tnl.IdentitySource,
) -> None:
    async with tnl.client(
        services=services, environment=environment, identity=identity
    ) as client:
        database = await client.connect("database")
        assert_type(database, tnl.PostgresConnection)
        # use the ordinary driver settings and close the driver before leaving
```

This is an interface sketch from the current source, not a qualified setup recipe.
Supply the exact server-qualified environment reference and separately approved
runtime identity; their concrete construction still needs the final SDK/authority
workflow. Neither the reference nor generated types grant access.

YAML, JSON, and evaluated TypeScript configurations all produce one immutable
service snapshot with exact names and protocol types. This typed client does not
need an `isinstance` check or a caller-supplied protocol. Generated private
overloads preserve the types; applications import no generated SDK object,
connection class, or factory.

Commit the shared `.tnl/generated/python/` outputs and dependency changes, and
regenerate after changing the shared service shape. Keep customer environment
references in runtime application data and private identity inputs in secret
storage, not in the generated snapshot. Publisher targets and credentials are not
generated client authority.
