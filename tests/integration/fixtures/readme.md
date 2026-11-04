# integration fixtures

Run these tasks from the repository root with `mise exec -- task <task>`.
The tasks and their test harnesses start and clean up the disposable containers.

| Fixture                                                                | Used by                                                        |
| ---------------------------------------------------------------------- | -------------------------------------------------------------- |
| [separated-stack/](separated-stack/)                                   | `go:test:load:runtime` and `go:test:load:connect`              |
| [dns/compose.yaml](dns/compose.yaml)                                   | `go:test:integration:dns`                                      |
| [compose-publisher/main.go](compose-publisher/main.go)                 | `go:test:integration:compose` and `go:test:integration:binary` |
| [publisher-install/test.Dockerfile](publisher-install/test.Dockerfile) | `go:test:integration:publisher-install`                        |

These need Docker. The binary tier requires Linux; publisher-install uses a
privileged Ubuntu/systemd container. Task definitions live in
[tasks/integration.yml](../../../tasks/integration.yml) and
[tasks/load.yml](../../../tasks/load.yml).
