# tnldotdev-tnl

take a shortcut through the internet.

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

Context exit joins native publication cleanup before stopping ASGI. Cancellation
also waits for an in-flight registration and cleanup; a lost registration reply
is reconciled using the same invocation identity. If `await tunnel.close()` fails,
the listener stays running so cleanup can be retried rather than dropping active
requests before the native publisher has drained.

For a configured app service, `tnl.run("myapp:app")` registers the listener
after Uvicorn binds it. Pass `service="api"` when the project has more than
one app service; the working directory selects the project, not the service.
Local publication needs no Git repository or origin. After changing project
configuration, stop and restart all apps and named local publishers for that
project together; the native owner retains one evaluated configuration.

See the [Python ASGI guide](https://tnl.dev/docs/publish#publish-a-python-asgi-app)
for FastAPI, visitor policy, limits, streaming, and WebSocket examples.

Use `db = await tnl.connect("database")` to prepare a declared service through
the native connection runtime. Every protocol, including HTTP and Kubernetes,
needs the wheel's matching native `tnl` binary. With `TNL_CONNECTION_HANDLE`
already prepared, `tnl.connect("database").snapshot()` reads its current settings
synchronously.
Run `tnl generate` and add `./.tnl/generated/python` as a project-local editable
dependency to use exact static service types with `from tnl_project import tnl`.
See the [Python connection boundary](connections.md) for lifecycle, TLS,
database-client adapters, and the generic TypeScript-factory boundary.
