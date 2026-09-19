# Glossary

This glossary defines the public vocabulary used by tnl documentation, CLI
output, configuration, and APIs. See [Architecture](ARCHITECTURE.md) for runtime
invariants and package ownership.

## System And Roles

| Term               | Meaning                                                                                                                              |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| tnl server         | The complete deployed system, including control, ingress, relays, and PostgreSQL.                                                    |
| `tnld` process     | One running daemon process configured with a server role.                                                                            |
| control            | The stateful `tnld` role that stores runtime state and manages placement, certificates, administration, and coordination.            |
| control service    | Interchangeable control processes sharing PostgreSQL.                                                                                |
| ingress            | The stateless `tnld` role that accepts visitors, applies route policy, selects a connected relay, and forwards each connection once. |
| ingress service    | Replicated ingress processes behind one health-aware ingress address.                                                                |
| relay              | The stateless `tnld` role that maintains publisher connections and carries visitor streams.                                          |
| relay service      | Interchangeable relay processes behind one relay address and sharing one intended failure boundary.                                  |
| standalone         | A `tnld` role that composes control, ingress, and two logical relay services in one process.                                         |
| authority API      | The API that owns identities, teams, memberships, invitations, domains, authentication, and authorization decisions.                 |
| built-in authority | The authority API served by control or standalone.                                                                                   |
| external authority | A separately deployed authority API used by a tnl server.                                                                            |

## People, Projects, And Routes

| Term            | Meaning                                                                                          |
| --------------- | ------------------------------------------------------------------------------------------------ |
| identity        | A person or administrator known to one tnl server.                                               |
| publisher       | The local `tnl publish` or `tnl dev` process.                                                    |
| visitor         | A browser or other client connecting to a public route.                                          |
| local service   | The developer's HTTP application.                                                                |
| target          | The local HTTP URL the publisher uses to reach the local service.                                |
| tunnel          | One `tnl publish` or `tnl dev` invocation and its lifecycle.                                     |
| project         | The selected directory, project configuration, and Git worktree.                                 |
| project service | A named local service with optional project-setting overrides.                                   |
| route           | The stored mapping from a public hostname to a target, policy, and state.                        |
| route session   | One publisher's server-side use of a route.                                                      |
| route version   | The ever-increasing number assigned to each new route session.                                   |
| ephemeral route | A route that expires after its tunnel stops.                                                     |
| enabled         | A stored route that has not been suspended or deleted.                                           |
| routable        | A route version with its certificate and enough ready publisher connections to receive visitors. |
| IP policy       | The rule controlling which visitor source addresses may use a route.                             |

## Connections And Addresses

| Term                       | Meaning                                                                         |
| -------------------------- | ------------------------------------------------------------------------------- |
| control URL                | The normalized HTTPS origin clients use to reach the control API.               |
| server domain              | The infrastructure DNS suffix for control, ingress, and relay hostnames.        |
| ingress address            | The public, health-aware address that sends visitor connections to ingress.     |
| relay address              | The stable public hostname and port used for a publisher connection.            |
| internal relay address     | The internal hostname and port ingress uses to forward visitor connections.     |
| publisher connection       | A long-lived multiplexed connection from a publisher to a relay.                |
| connection slot            | One of the two publisher connections maintained by a route session.             |
| connection assignment      | Control's assignment of a connection slot to a relay service and relay address. |
| connected relay            | The relay process holding a publisher connection.                               |
| ready publisher connection | An authenticated, current publisher connection that can carry visitor streams.  |
| visitor connection         | One public TCP connection from a visitor to a route hostname.                   |
| visitor stream             | One multiplexed stream carrying a visitor connection through a relay.           |
| transport                  | QUIC or TLS/TCP with yamux, used to carry a publisher connection.               |

## Coordination And Security

| Term                        | Meaning                                                                              |
| --------------------------- | ------------------------------------------------------------------------------------ |
| ingress lease               | Control's time-limited permission for an ingress process to serve traffic.           |
| relay lease                 | Control's time-limited permission for a relay process to accept work.                |
| process run ID              | The identifier generated each time an ingress or relay process starts.               |
| placement                   | Control's choice of different relay services for a route session's connection slots. |
| draining                    | Rejecting new work while allowing existing connections to finish until a deadline.   |
| cluster authentication      | Authentication with a shared cluster secret among control, ingress, and relays.      |
| hosted secret               | The secret shared only by control and an external authority.                         |
| storage key                 | The key control uses to encrypt recoverable secrets in PostgreSQL.                   |
| control session             | A revocable login session with an access token and refresh token.                    |
| relay transport certificate | The exact-hostname WebPKI certificate shared by a relay service.                     |

## Teams And Domains

| Term                      | Meaning                                                                                               |
| ------------------------- | ----------------------------------------------------------------------------------------------------- |
| team                      | The ownership and authorization boundary for domains and routes.                                      |
| membership                | An identity's relationship to a team, including its role and member slug.                             |
| member namespace          | A hostname built from a membership and team domain.                                                   |
| managed deployment domain | A server-controlled domain used to generate member namespaces.                                        |
| claimed domain            | A domain assigned to one team after DNS authority verification.                                       |
| team domain               | A managed deployment domain or claimed domain available to one team.                                  |
| shared route              | A team-owned route outside individual member namespaces.                                              |
| route scope               | Whether a route belongs to one membership or to the team collectively.                                |
| maintenance control       | An administrator-controlled gate for route creation, route-session creation, or certificate issuance. |
