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
    async with tnl.publish(app) as tunnel:
        print(tunnel.url)
        await tunnel.finished()


asyncio.run(main())
```

Run `uv run python preview.py`. tnl starts the app and waits until its temporary
public URL can receive visitors. Press Ctrl+C to remove the URL and stop the
app. By default, visitors need a current sign-in, share link, or token.

`status()` reads without probing. `wait()` requests fresh application readiness;
`wait(until="routable")` checks only routing. `finished()` waits for termination.
`watch(after=status.cursor)` resumes native events exclusively after that cursor;
omit `after` to begin with a current snapshot. Cancelling an observation does not
stop the publication. Close the publication, or leave its async context, to drain
its native run before stopping the SDK-owned ASGI listener.

To use a provisioned publisher credential instead of local setup, pass
`publisher_credential_file="/absolute/private/publisher.json"` to `tnl.publish`, or
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

For a listener you manage yourself, `await prepared.register(target)` returns the
same `Publication` handle without waiting for public readiness. Replacing its
listener supersedes the old handle; closing the old handle cannot stop the
replacement. A failed drain remains retryable with `close()`.

## connect to a service

Use `await tnl.connect("database")` to get settings for a declared service.
The platform wheel includes the native tnl binary required for every protocol.
See [Python connection examples](https://github.com/tnldotdev/tnl/blob/main/packages/py/connections.md) for PostgreSQL, TCP, Kubernetes,
and the current MySQL and HTTP adapter limits.
