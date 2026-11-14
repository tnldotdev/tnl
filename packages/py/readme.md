# tnldotdev-tnl

Give a Python ASGI app a public URL with tnl. Install the [tnl CLI](https://tnl.dev/docs/releases) first, then:

```sh
uv add tnldotdev-tnl
tnl auth login
tnl publisher setup --namespace
```

With an ASGI app named `app` in `myapp.py`, run this script with `uv run python preview.py`:

```python
import asyncio
import tnl
from myapp import app

async def main():
    client = tnl.create_client(project="my-team/my-project")
    async with client.deployment("local") as local:
        async with await local.publish(app) as publication:
            print(publication.url)
            await publication.wait()

asyncio.run(main())
```

Stop the script to remove the temporary URL. `publish("web", app)` uses a configured local service or an approved saved remote URL. Remote publication requires a registered deployment credential; connection-only sources cannot publish. The returned `Publication` is routable, supports `wait()` and retryable `aclose()`, and is an async context manager.

See the [publishing guide](https://tnl.dev/docs/publish), [quickstart](https://tnl.dev/docs), and [main README](https://github.com/tnldotdev/tnl#readme).
