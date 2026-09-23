# runtime workload assertion inventory

The separated topology is the canonical runtime workload. These checks must survive
the retirement of the aggregate workload; database-specific checks belong to the
local coordinator, not the shared publisher or visitor implementation.

| Assertion                                                                        | Owner after migration                       |
| -------------------------------------------------------------------------------- | ------------------------------------------- |
| Verified route TLS, observed hostname, complete deterministic response           | Shared visitor                              |
| Every elapsed offer counted; bounded queue and request deadline                  | Shared visitor scheduler                    |
| Held streams alive before fault; breaks and survivors recorded                   | Shared visitor / scenario                   |
| Fresh visitors succeed while a forwarding or publisher-path drop stays installed | Coordinator phase barriers / shared visitor |
| Fresh visitors succeed after abrupt relay process exit                           | Coordinator phase barriers / shared visitor |
| Healthy-path held streams survive and receive bytes during a blackhole           | Shared held-stream byte counter / scenario  |
| Actual UDP drops force TCP fallback and abandoned QUIC sockets close             | Publisher observations / deployment runner  |
| Targeted latency/loss reaches both directions of an exercised path               | Deployment runner qdisc/filter evidence     |
| Local scheduling uses monotonic time; negative durations are rejected            | Shared visitor / timing regressions         |
| Every route serves after recovery, including unsampled routes                    | Visitor correctness phase                   |
| Route versions unchanged after recovery                                          | Local coordinator SQL assertion             |
| One CA order and installed issuance per route                                    | Local coordinator and control counter       |
| Two current publisher connections per route after repair                         | Local coordinator SQL assertion             |
| Healthy routes serve during partial publisher shutdown                           | Shared visitor / shutdown phase             |
| Bounded startup and shutdown, including partial activation failure               | Shared publisher group                      |
| Joined cancellation and close failure remains a failure                          | Shared publisher regression                 |
| Unexpected publisher or component exit aborts the run                            | Publisher group / deployment runner         |
| Zero active sessions, connections, and reservations after shutdown               | Local coordinator SQL assertion             |
| Final ingress usage flush, complete coverage, report/aggregate equality          | Local coordinator SQL assertion             |
| Per-component resources, raw metrics, bounded failure evidence                   | Deployment runner                           |
| Disposable infrastructure cleanup on success and failure                         | Deployment runner                           |

The four-route smoke exercises both QUIC and TLS/TCP. The 64-route reference uses
128 visitor workers and eight waiting slots; historical eight-worker results are
not measurements of this profile.
