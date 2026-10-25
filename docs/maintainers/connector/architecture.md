# connector architecture

The connector owns a native visitor's connection to an approved service.
It selects the exact service, prepares authenticated ingress paths and a local
listener or stdio stream, and joins their cleanup. Publishing a service is a
separate role even when the same native owner supports both SDK capabilities.

## implementation map

| Owner                           | Responsibility                                                                                                                                                                     |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `internal/connector`            | Reusable context/service selection, foreground/installed operations, detached owner launch/backend, preparation, profile validation, handle operations, stdio, and joined shutdown |
| `internal/connector/stream`     | Device/workload control adapter, assignment reservation/recovery, accepted peers, two ingress paths, inner TLS, bytes, and half-close                                              |
| `internal/connector/runtime`    | Bounded private owner IPC, handle validation, owner lock, atomic prepared snapshots, listener generations, and terminal close                                                      |
| `internal/connector/workload`   | Ephemeral key, provider assertions, exchange/refresh, immutable session binding, and fixed expiry                                                                                  |
| `internal/connector/kubeconfig` | Owned context projection, selected-user credentials, bounded exec helpers, locks, and cleanup                                                                                      |
| `internal/client/supervisor`    | Shared installed-job registry and supervisor scheduling                                                                                                                            |

Root operations compose the stream/runtime children. Stream mechanics do not
import root operations. The runtime accepts a narrow backend contract; it does
not import commands or the concrete backend. `cmd/tnl` retains flags, selected
inputs, prompts, human/JSON output, and dispatch. The connector owns listeners,
adapters, sessions, readiness, retries, and cleanup. Semantic readiness callbacks
do not transfer that ownership to command presentation.

## selection and transport identity

Configured local selection reads control's exact canonical-directory worktree
realization, then chooses that immutable service ID from visitor inventory.
Applied selection binds source fingerprint and configuration key. Friendly names
never adopt another project's service. Lookup does not apply configuration or
realize a new service. Inventory is authorization-filtered and bounded; an offline
service may be visible without being ready.

The local dial address and approved managed hostname/port remain separate.
Changing `--listen` changes only the loopback listener. Native clients retain
certificate/name verification; HTTP keeps the managed Host/SNI and allocated
port while dialing loopback. Opaque clients use the verified TLS helper. An
ordinary connection never exports application client certificates. Explicit
certificate export remains a client-state operation with its own key/CSR/storage
locks.

Preparation checks approved protocol, service/run, assignment, trust revision,
and accepted transport peer before bytes. The connector authenticates two
ingress paths; ingress observes the source and authorizes each visitor stream.
Startup retries a transient preflight failure for at most ten seconds while
ingress finishes preparing the path; denied access or rejected TLS fails at
once. Only a verified preflight reports ready.
ingress and publisher verify signed permission and exact reservations locally.
the connector sends its proof-bound opening with bounded initial TLS bytes,
without waiting for a per-stream acceptance. server-first protocols send an
empty opening immediately. an ambiguous opening write cannot create another
target connection on the sibling path. the connector does not interpret
publisher-to-target CA trust. stream failure, metadata reload, and listener
replacement never replay an admitted application stream.

## process and request lifetime

Prepared reads publish metadata and transport identity atomically. They do not
start network work or wait for an unrelated sibling's preparation/assertion.
Explicit preparation may wait at its own bounded gate. Listener replacement
cancels and joins the previous generation; terminal close cannot revive accepts.
Owner recovery requires release of the previous lifetime lock.

Detached startup uses a bounded private readiness handshake and filtered child
environment. Failed delivery cleans up the child. Handles reject unsafe files,
permissions, symlinks, FIFO reads, wrong ownership/proof, and expired capabilities.
Private IPC is implementation, not an SDK extension API. Stdio stdout carries
only application bytes; diagnostics go to stderr. EOF, remote close, and
cancellation join both copy and transport owners.

Human process lifetime is distinct from workload session lifetime. Workload
assertion acquisition, refresh, connector renewal, certificate renewal, and
reconnection cannot extend the original fixed session window or replace its
verified subject. Late results cannot resurrect an expired/replaced owner.
Shutdown shares the caller's cleanup budget across assignment release and session
revocation, and joins operation/renewal workers before releasing owned context.

See [the native IPC and lifecycle contract](connection-runtime.md),
[platform SDK access](platform-access.md), [Kubernetes contexts](kubernetes-native.md),
[workload authority](../control/workload-sessions.md), and
[local Vercel qualification](vercel-functions.md). Built-owner black-box suites
live in `tests/integration/connector`; white-box owner/re-exec tests stay beside
the implementation and use test-only `internal/testutil/connectorfixture`.
