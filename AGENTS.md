# Canonical Terminology

Use these terms consistently in code, APIs, CLI help, and documentation.

| Term | Meaning |
| --- | --- |
| tnl server | The deployed service as a whole. Never call it Core. |
| `tnld` process | One running daemon process. |
| control API | The server HTTP API used by clients and administrators. |
| standalone | A `tnld` role providing the control API, ingress, durable state, certificates, and in-process forwarding. |
| edge | A stateful `tnld` role providing the control API, ingress, durable state, certificates, and worker coordination. |
| worker | A stateless `tnld` role that hosts worker backends and connects outbound to an edge. |
| local service | The developer's HTTP application. |
| target | The loopback URL used by the publisher to reach the local service. |
| publisher | The local `tnl publish` or `tnl dev` process. |
| worker backend | The internal forwarding attachment connecting ingress to a publisher. |
| tunnel | One local `publish` or `dev` invocation and its lifecycle. |
| route | The durable server-side mapping from a public hostname to a publisher. |
| route session | One live publisher attachment for a route. |
| route version | The monotonic number identifying successive route sessions; use `route_version` in machine formats and `RouteVersion` in code. |
| enabled | A durable route that is not suspended or deleted. |
| routable | A route version currently ready to receive ingress traffic. |
| hostname | A complete DNS name exposed by tnl. |
| deployment hostname suffix | The DNS suffix under which a server allocates managed hostnames. |
| managed hostname | A persistent hostname claimed under the deployment hostname suffix. |
| custom domain | An externally owned DNS domain claimed after DNS verification. |
| child hostname | A hostname below a claimed managed hostname or custom domain. |
| temporary hostname | A server-generated hostname for one publish invocation. |
| identity | A server-local authorization principal. Login-token access uses the built-in administrator identity; each OIDC issuer/subject pair maps to a distinct identity. |
| maintenance control | An administrator-controlled gate for route creation, route-session creation, or certificate issuance. |
| Tailcat | The encrypted transport between a publisher and worker backend. |
| DERP relay | A Tailscale relay used by Tailcat when a direct path is unavailable. |
| route usage bucket report | A transmitted report for one route, route version, time bucket, and report revision. |

- Never introduce `Core` as a tnl architectural term. Use server, `tnld` process, control API, edge, or authorization receiver as appropriate.
- Avoid unqualified `name`, `base`, `session`, `version`, and `active` when a canonical term above is more precise.
- Reserve `generation` for internal mutation counters; public route counters are route versions.
