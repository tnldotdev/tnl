# python connections

Create a project-bound client and select a deployment to reach a declared
service. Local HTTP, TCP, MySQL, PostgreSQL, and Kubernetes connections need
no account. Remote access uses a registered credential, a job-owned connection
handle, or an approved provider workload. See the [AWS publisher guide](https://tnl.dev/docs/aws-publishers)
for one way to run a publisher beside your database.

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
    client = tnl.create_client(
        project="acme/demo",
        services={"database": {"protocol": "postgres"}},
    )
    async with client.deployment("production") as deployment:
        db = await deployment.connect("database")
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

client = tnl.create_client(
    project="acme/demo", services={"ssh": {"protocol": "tcp"}}
)
async with client.deployment("production") as deployment:
    stream = await deployment.connect("ssh")
    assert isinstance(stream, TCPConnection)
    with socket.create_connection((stream.host, stream.port), timeout=10) as connection:
        banner = connection.recv(256)
```

- **Kubernetes:** Use the returned `kubeconfig` and `context`, including the
  kubeconfig's native credential plugin.
- **MySQL:** Settings include a verified `ssl.SSLContext`, but there is no
  drop-in PyMySQL/mysqlclient adapter. A driver must dial `host` while verifying
  `server_hostname`. Passing the loopback address as the TLS name fails verification.
- **HTTP:** There is no bundled HTTPX transport. For a remote service, an
  adapter must dial the local connector while preserving the managed origin,
  TLS name, and request authorization. Passing the returned `url` to an
  ordinary HTTP client is insufficient.

For local services, use `client.deployment("local")`. Its settings describe the
local listener without starting a publisher connection or requiring sign-in.

## keep connections current

Call `await deployment.connect("database")` for fresh settings when replacing a
connection or pool. tnl does not update an existing pool or replay failed
queries. Create a deployment handle inside each serving worker after a fork.

Close database clients before `await deployment.aclose()`. Closing stops only
the connector owned by this handle. A job-owned connector supplied through
`TNL_CONNECTION_HANDLE` remains the job's responsibility.

## typed service names

```console
tnl generate
uv add --editable ./.tnl/generated/python
```

For YAML and JSON configurations, `from tnl_project import create_client, deployment`
supplies declared service facts and typed connection methods:

```python
client = create_client(project="acme/demo")
production = deployment(client, "production")
database = await production.connect("database")
```

For a TypeScript configuration, supply `services` to `create_client` explicitly;
evaluated factory results cannot provide stable facts across worktrees. Commit
`.tnl/generated/python/` and regenerate after changing services.
