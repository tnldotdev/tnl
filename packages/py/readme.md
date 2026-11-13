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
    client = tnl.create_client(project="acme/shop")
    async with client.deployment("local") as local:
        async with await local.publish(app) as publication:
            print(publication.url)
            await publication.wait()


asyncio.run(main())
```

Run `uv run python preview.py`. tnl starts the app and waits until its temporary
public URL can receive visitors. Press Ctrl+C to remove the URL and stop the
app. By default, visitors need a current sign-in, share link, or token.

For local namespace setup from a provisioned publisher, set
`TNL_PUBLISHER_CREDENTIAL_FILE`. For staging or production, configure an approved
`TNL_TOKEN` and select `client.deployment("production")`.
`await deployment.publish("web", app)` serves its saved URL;
`await deployment.publish(app)` allocates a temporary one. See
[application publication](https://tnl.dev/docs/api#approve-application-publication).

## use a configured app

Declare an app service in `tnl.yml`:

```yaml
version: 1
tnl:
  services:
    api: { protocol: http }
  deployments:
    local:
      targets:
        api: { type: app, public_url: {} }
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
