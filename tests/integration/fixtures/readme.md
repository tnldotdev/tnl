# disposable integration fixtures

These files support explicit integration/load Tasks. run those Tasks from the
repository root so the harness owns startup and cleanup.

| fixture                                                   | owner and public task                                                                                              |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `separated-stack/compose.yaml`, `runtime-load.Dockerfile` | `tools/testharness`, `go:test:load:runtime`                                                                        |
| `dns/compose.yaml`                                        | `tools/testharness`, `go:test:integration:dns`                                                                     |
| `compose-publisher/main.go`                               | publisher target and daemon binary integration tests, `go:test:integration:compose` / `go:test:integration:binary` |
| `publisher-install/test.Dockerfile`                       | privileged disposable Ubuntu/systemd, `go:test:integration:publisher-install`                                      |

Compose build contexts and repository mounts climb four levels to the root.
daemon runtime assertions remain beside daemon composition, including their
private helpers; these fixture moves do not make daemon internals public.
