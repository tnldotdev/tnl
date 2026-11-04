# integration fixtures

run these tasks from the repository root with `mise exec -- task <task>`.
the tasks and their test harnesses start and clean up the disposable containers.

| fixture                                                                | used by                                                        |
| ---------------------------------------------------------------------- | -------------------------------------------------------------- |
| [separated-stack/](separated-stack/)                                   | `go:test:load:runtime` and `go:test:load:connect`              |
| [dns/compose.yaml](dns/compose.yaml)                                   | `go:test:integration:dns`                                      |
| [compose-publisher/main.go](compose-publisher/main.go)                 | `go:test:integration:compose` and `go:test:integration:binary` |
| [publisher-install/test.Dockerfile](publisher-install/test.Dockerfile) | `go:test:integration:publisher-install`                        |

these need Docker. the binary tier requires Linux; publisher-install uses a
privileged Ubuntu/systemd container. task definitions live in
[tasks/integration.yml](../../../tasks/integration.yml) and
[tasks/load.yml](../../../tasks/load.yml).
