# tnldotdev-tnl

Start a configured Python ASGI app with a saved public URL. Install
the wheel for your macOS or Linux arm64 or x64 machine:

```console
uv add tnldotdev-tnl
```

Add a `dev.py` alongside the app and use the same file in every worktree:

```python
from tnl.uvicorn import run

run("app:app", service="web", host="127.0.0.1", port=0, reload=True)
```

```console
uv run python dev.py
```

Define `web` as an app service in your project configuration. Uvicorn owns the
listener; the serving worker registers its actual bound port after startup and
unregisters before shutdown. The reloader does not publish from its parent.

For a temporary public URL outside configured services, sign in to tnl and use
`async with tnl.open(app)`. The native local publisher obtains a namespace grant
for the selected project; the ASGI app only uses a scoped local HTTP credential.
The context starts ASGI lifespan before publishing, waits for the URL to become
routable, and removes it on exit.

See the [Python ASGI guide](https://tnl.dev/docs/publish#publish-a-python-asgi-app)
for FastAPI, visitor policy, limits, streaming, and WebSocket examples.
