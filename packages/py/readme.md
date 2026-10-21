# tnldotdev-tnl

Use a Python ASGI app to publish a temporary public URL through tnl. Install
the wheel for your macOS or Linux arm64 or x64 machine:

```console
uv add tnldotdev-tnl
```

Set up a namespace publisher once, then use `async with tnl.open(app)`:

```console
tnl publisher setup --namespace
```

`open` starts ASGI lifespan before publishing, waits for the URL to become
routable, and removes it when the context exits. The native publisher selects
the locally provisioned namespace identity, or `TNL_PUBLISHER_FILE` if set.
Pass `publisher_file="/absolute/private/publisher.json"` or
`publisher_id="pub_..."` to select one explicitly. A configured invalid file
fails instead of falling back to another identity. The native publisher keeps
its signing key private; it never enters app metadata or status.

For a configured app service, `tnl.run("myapp:app")` registers the listener
after Uvicorn binds it. Pass `service="api"` when the project has more than
one app service; the working directory selects the project, not the service.

See the [Python ASGI guide](https://tnl.dev/docs/publish#publish-a-python-asgi-app)
for FastAPI, visitor policy, limits, streaming, and WebSocket examples.

Use `db = await tnl.connect("database")` to prepare a declared service through
the native connection runtime. With `TNL_CONNECTION_HANDLE` already prepared,
`tnl.connect("database").snapshot()` reads its current settings synchronously.
Run `tnl generate` and add `./.tnl/generated/python` as a project-local editable
dependency to use exact static service types with `from tnl_project import tnl`.
See the [Python connection boundary](connections.md) for lifecycle, TLS,
database-client adapters, and the generic TypeScript-factory boundary.
