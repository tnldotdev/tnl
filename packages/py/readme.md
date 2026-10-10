# tnldotdev-tnl

Use a Python ASGI app to publish a temporary public URL through tnl. Install
the wheel for your macOS or Linux arm64 or x64 machine:

```console
uv add tnldotdev-tnl
```

Run `tnl url credential create --ephemeral` after signing in, then set
`TNL_CREDENTIAL` in your app environment. `async with tnl.open(app)` starts
ASGI lifespan before publishing, waits for the URL to become routable, and
removes it when the context exits.

See the [Python ASGI guide](https://tnl.dev/docs/publish#publish-a-python-asgi-app)
for FastAPI, visitor policy, limits, streaming, and WebSocket examples.
