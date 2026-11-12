# tnldotdev-tnl

Give your Python ASGI app an HTTPS URL through tnl. Requires Python 3.12+
on macOS or Linux, arm64 or x64.

## publish an asgi app

Install the [tnl CLI](https://tnl.dev/docs/releases) for setup, then add the SDK and
prepare a namespace publisher:

```console
uv add tnldotdev-tnl
tnl auth login
tnl publisher setup --namespace
```

If your ASGI app lives in `myapp.py`, save this as `preview.py`:

```python
import asyncio

import tnl
from myapp import app


async def main():
    async with tnl.open(app) as tunnel:
        print(tunnel.url)
        await tunnel.wait()


asyncio.run(main())
```

Run `uv run python preview.py`. tnl starts the app and waits until its temporary
public URL can receive visitors. Press Ctrl+C to remove the URL and stop the
app. By default, visitors need a current sign-in, share link, or token.

To use a provisioned publisher credential instead of local setup, pass
`publisher_credential_file="/absolute/private/publisher.json"` to `tnl.open`, or
set `TNL_PUBLISHER_CREDENTIAL_FILE`.

## use a configured app

Declare an app service in `tnl.yml`:

```yaml
version: 1
tnl:
  services:
    api:
      public_url: {}
      target:
        type: app
```

Then start it with Uvicorn through tnl:

```python
import tnl

if __name__ == "__main__":
    tnl.run("myapp:app", service="api", port=0, reload=True)
```

Run from the project directory. `service="api"` selects the service above.
`port=0` picks a free port, and
`tnl wait` checks public readiness. Restart the project's apps together after
changing configuration.

## connect to a service

Use `await tnl.connect("database")` to get settings for a declared service.
The platform wheel includes the native tnl binary required for every protocol.
See [Python connection examples](https://github.com/tnldotdev/tnl/blob/main/packages/py/connections.md) for PostgreSQL, TCP, Kubernetes,
and the current MySQL and HTTP adapter limits.

For a deployed app, run `tnl generate` and install its generated facts:

```console
uv add --editable ./.tnl/generated/python
```

Then construct an independent client with an approved environment reference and
visitor identity. This example rereads an explicitly selected OIDC token file:

```python
import asyncio
from pathlib import Path

import tnl
from tnl_project import services


async def assertion(challenge: tnl.IdentityChallenge) -> str:
    return (await asyncio.to_thread(Path("/var/run/secrets/tnl/token").read_text)).strip()


async def connect_database() -> None:
    async with tnl.client(
        services=services,
        environment=tnl.EnvironmentReference(
            "https://control.example", "catalog", "env_1234567890123456789012"
        ),
        identity=tnl.IdentitySource("oidc", "mwp_1234567890123456789012", assertion),
    ) as client:
        database = await client.connect("database")
        # pass database's address and verified TLS settings to your driver.
        print(database.host, database.port)
```

Use your server's saved reference and visitor permission, not these example
values. Generated facts supply names and protocols; they grant no access and
contain no targets or credentials. The client never selects an environment from
the working directory or a mutable process-wide default. Closing it leaves other
clients and local `tnl.connect` alone. A `registered-key` identity callback signs
the native challenge's `scope` and `audience` using its registered identity key,
not a publisher credential or the native session key.
