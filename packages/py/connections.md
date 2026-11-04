# python connections

Use `tnl.connect` from your project directory to reach a declared service.
Start the service's publisher and run `tnl auth login` with an identity that can
visit it. See the [AWS publisher guide](https://github.com/tnldotdev/tnl/blob/main/deploy/publisher/fargate/readme.md)
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

Replace `import tnl` with `from tnl_project import tnl`, keeping the connection
class imports used above. YAML and JSON configurations generate
exact service names and protocol types. TypeScript configurations return a union;
narrow it with `isinstance`, as above. Commit `.tnl/generated/python/` and the
dependency changes, and regenerate after changing services.
