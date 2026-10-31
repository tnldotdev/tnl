# connector architecture

The connector owns a native visitor's connection to an approved service.
It selects the exact service, prepares two authenticated relay carriers and a local
listener or stdio stream, and joins their cleanup. Publishing a service is a
separate role even when the same native owner supports both SDK capabilities.

## implementation map

| Owner                           | Responsibility                                                                                                                                                                     |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `internal/connector`            | Reusable context/service selection, foreground/installed operations, detached owner launch/backend, preparation, profile validation, handle operations, stdio, and joined shutdown |
| `internal/connector/stream`     | Device/workload control adapter, signed pair ownership, two relay carriers, retained inner QUIC, prepared openings, visitor TLS, bytes, and half-close                             |
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

preparation checks the approved service/run, protocol, trust revision, and exact
relay-process assignments. each relay claims the connector's accepted socket
source; both claims must agree. control delivers that binding to the publisher,
which installs its packet registrations and inner QUIC listener before reporting
preparation. connector readiness also requires the actual inner QUIC handshake.

startup retries the original signed creation within its original deadline; it
does not sign a replacement owner. pair renewal cannot extend the publisher's
independently observed installation deadline. both failed fixed carriers end the
packet endpoint immediately; a single failure leaves the warm sibling usable.

the connector prepares signed application openings before local arrival. the
publisher checks each opening against its installed pair and current signed
permission before target resolution, dialing, or a server-first greeting. the
connector does not interpret publisher-to-target CA trust. an outer carrier loss
can switch packet delivery to the warm sibling without changing the inner QUIC
session or target socket. it cannot reconnect a carrier in place or transfer an
admission to another assignment, source, pair, or run. stream failure, metadata
reload, and listener replacement never replay application bytes.

the publisher's bounded frame reader consumes permission renewals independently
of application reads, including response-only HTTP. a newer verified revision
waits only for local background policy under the existing guard's unchanged bound.
it performs no RPC, grants nothing early, and cannot revive expiry.

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
Shutdown shares the caller's cleanup budget across owned transport cleanup and session
revocation, and joins operation/renewal workers before releasing owned context.

See [the native IPC and lifecycle contract](connection-runtime.md),
[platform SDK access](platform-access.md), [Kubernetes contexts](kubernetes-native.md),
[workload authority](../control/workload-sessions.md), and
[local Vercel qualification](vercel-functions.md). Built-owner black-box suites
live in `tests/integration/connector`; white-box owner/re-exec tests stay beside
the implementation and use test-only `internal/testutil/connectorfixture`.
