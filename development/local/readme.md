# local contributor stack

Run the public Tasks from the repository root:

```console
mise exec -- task local:up
mise exec -- task local:trust
mise exec -- task local:login
```

The Compose file, development DNS/OIDC Dockerfiles, admission fixture, proxy
configuration, and Pebble certificate/configuration belong to this stack.
its build contexts point to the repository root; private host certificates and
isolated client state stay in `.local` there.

`local:trust` changes the macOS login keychain. `local:down` preserves state;
`local:reset` removes trust, containers, volumes, and `.local`.

See [contributing](../../contributing.md#try-the-local-stack) for the development
workflow. deployable server templates live under `deploy/server`.
