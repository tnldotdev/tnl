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
    async with tnl.open(app) as tunnel:
        print(tunnel.url)
        await tunnel.wait()

asyncio.run(main())
```

Stop the script to remove the temporary URL. See the [publishing guide](https://tnl.dev/docs/publish), [quickstart](https://tnl.dev/docs), and [main README](https://github.com/tnldotdev/tnl#readme).
