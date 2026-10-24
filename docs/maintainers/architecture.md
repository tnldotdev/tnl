# architecture

Use the owning boundary below when changing a lifecycle, authorization decision,
or contract. This is the contributor map of the implemented tree. Public
introductions and operational procedures live in [how tnl works](https://tnl.dev/docs/how-it-works),
[self-hosting](https://tnl.dev/docs/self-hosting), and the
[`tnld` reference](https://tnl.dev/docs/tnld).

```text
                               PostgreSQL
                                   ^
                                   |
tnl clients ------------------> control
                                   |
                          routing  |  placement
                                   v
visitor ---> ingress ----------------> relay <=== publisher ---> target
                                      A or B
```

Control owns durable server state and current authorization. Ingress receives
short-lived routing projections; a relay owns its current lease and connected
publishers. Visitor TLS ends at the publisher. A connector is the visitor-side
native operation for services; it is separate from publishing even when
one local `tnl` process composes both capabilities.

## find the owner

| Boundary                    | Implementation and responsibility                                                                                                                                                           | Maintainer reference                                    |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| Publisher                   | `internal/publisher`: publication, visitor TLS, admission, target forwarding; children own app, local process/API, invocations, groups, identity, integrations, targets, and browser assets | [publisher architecture](publisher/architecture.md)     |
| Connector                   | `internal/connector`: service selection, native owner, preparation, loopback/stdio, cleanup; children own stream mechanics, IPC, workload sessions, and kubeconfig                          | [connector architecture](connector/architecture.md)     |
| Control                     | `internal/control`: public/authority/private APIs, PostgreSQL transactions, placement, authorization, certificates, DNS, OIDC, delivery, retention                                          | [control architecture](control/architecture.md)         |
| Transport, ingress, relay   | `internal/transport` supplies mechanics; `internal/ingress` owns visitor admission and retry commitment; `internal/relay` owns connected publisher claims and streams                       | [transport architecture](transport/architecture.md)     |
| Composition and development | `internal/daemon`, `internal/client`, static config and shared leaves; test/build/generator/Task ownership                                                                                  | [development architecture](development/architecture.md) |
| Releases and artifacts      | SDK/native packages, archives, wheels, installer, action, and deployment handoff                                                                                                            | [release architecture](releases/architecture.md)        |

`cmd/tnl` owns command input and presentation, `cmd/tnld` starts the daemon, and
`cmd/tnlbench` drives shared benchmark workloads. An executable does not determine
the role of everything it calls: `tnl publish` composes publisher operations,
`tnl connect` composes connector operations, and `tnl apply` sends control an
evaluated configuration. The daemon composes control, ingress, and relay.
Standalone runs those same boundaries and two logical relay services in one
process against PostgreSQL.

## dependency direction

```text
commands and daemon composition
              v
role operations and API adapters
              v
owned runtime/state and focused role leaves
              v
shared policy, security, naming, failure, telemetry, transport
              v
public contracts and external libraries
```

This is an ownership rule, not a requirement to pass through every layer.
Directory parents are not convenience-import packages. Shared leaves do not
import commands, daemon startup, role orchestrators, HTTP handlers, or control
state. Generated contracts do not import implementations. When a dependency
would point upward, move the actual value/operation to its lower owner, define
a narrow interface with its consumer, or compose above both users. Avoid generic
shared packages, callbacks exposing an entire root's state, and internal old-path
facades.

For example, `publisher/local` constructs app workers and the private HTTP API;
`publisher/localapi` imports app state and its protocol, not the process owner.
Connector root operations compose `connector/stream`, whose accepted assignment
and peer values do not require root operation state. Control API adapters use
state operations; state transactions do not call HTTP handlers. Ingress and relay
use coordination contracts and projections, never control's database package.

## own each http surface

Each entrypoint owns its `paths/` and `schemas/` fragments. The ingress and relay
coordination contracts are served by control, not by those roles' visitor
listeners.

| Source                                                                               | Server and caller                                                                                     | Canonical generated Go package             |
| ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| [public control](../../api/control/public/v1/openapi.yaml)                           | `internal/control/api/public`; CLI and native publisher credentials                                   | `pkg/api/control/public/v1`                |
| [authority](../../api/control/authority/v1/openapi.yaml)                             | `internal/control/api/authority`; identity, sessions, teams, domains, company and workload operations | `pkg/api/control/authority/v1`             |
| [private ingress coordination](../../api/control/private/ingress/v1/openapi.yaml)    | `internal/control/api/private/ingress`; cluster-authenticated ingress or standalone direct adapter    | `pkg/api/control/private/ingress/v1`       |
| [private relay coordination](../../api/control/private/relay/v1/openapi.yaml)        | `internal/control/api/private/relay`; cluster-authenticated relay or standalone direct adapter        | `pkg/api/control/private/relay/v1`         |
| [publisher browser](../../api/publisher/browser/v1/openapi.yaml)                     | Publisher same-origin browser operations after current visitor authorization                          | `pkg/api/publisher/browser/v1`             |
| [local publisher](../../api/publisher/local/v1/openapi.yaml)                         | `internal/publisher/localapi`; scoped private native registration and observation                     | `pkg/api/publisher/local/v1`               |
| [public URL usage receiver](../../api/integrations/public-url-usage/v1/openapi.yaml) | External receiver; control usage worker sends authenticated reports                                   | `pkg/api/integrations/public-url-usage/v1` |

Each contract generates one package beside its generator configuration. The Go
SDK's `PublisherIdentity` is an opaque prepared identity; it does not expose an
internal control client or key. `pkg/protocol/tunnelv1` owns the handwritten
tunnel messages and framing.

OpenAPI defines wire shapes, not a promise that every reserved operation is
implemented. Identical shapes reference their existing source, usually public
control schemas. The tunnel protocol is handwritten and tested with golden JSON,
framed-wire fixtures, invalid input, bounds, fuzzing, and common transport behavior.
See [generator ownership](../../contributing.md#edit-generated-sources) for source
bundling and external consumers.

## preserve runtime and trust boundaries

- Control alone owns PostgreSQL, storage-key, DNS, ACME, mailer, and authority
  configuration. Ingress and relay never receive `TNLD_STORAGE_KEY`.
- Control checks the exact embedded schema version and baseline identity before
  serving. Migration uses the direct URL; serving uses the pooled URL. The
  current PostgreSQL baseline requires a fresh database and coordinated server
  stop/start.
- Publisher connection slots use different relay services. Initial routability
  needs the certificate and both connections; afterward one ready connection can
  sustain service while the other is replaced.
- [region catalog](../../internal/region/catalog.json) codes identify geography,
  not a provider or authority boundary. ingress and relay registrations use a
  checked tnl code; unlocated self-hosted processes use `local`. providers map to
  these codes explicitly. preferences select from currently live, capacity-eligible
  processes; a failed preferred region falls back without granting visit access.
  one relay service stays in one region, and its connection slots still belong to
  different relay services. each private ingress address must reach its exact
  assigned process; two hostnames on a load-balanced app are not two paths.
- Ingress creates PROXY v2 metadata once; relay preserves it. No application
  bytes are replayed after the first visitor byte sent to a relay.
- A copied relay lease deadline is a routing observation. The connected relay
  checks its current lease, process identity, and exact connection claim before
  accepting a stream.
- Visitor TLS, relay transport TLS, connector authentication, and
  publisher-to-target TLS are separate trust boundaries. Application
  authentication remains application-owned.
- Current authorization, fixed workload expiry, drain/join ordering, and
  registration/run/target freshness survive process and package moves.
- Public URL DNS points to ingress, independently of relay placement.

The [domain plan](domain-boundaries-plan.md) and
[organization plan](reorganization-plan.md) describe the accepted scope.
