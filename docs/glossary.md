# glossary

These are the terms most often used by tnl commands, configuration, and APIs.
Each guide still explains a term when it first matters.

## local development

| Term            | Meaning                                                             |
| --------------- | ------------------------------------------------------------------- |
| Identity        | A person or administrator known to one tnl server.                  |
| Publisher       | The local `tnl publish` or `tnl dev` process.                       |
| Visitor         | A browser or other client connecting to a public route.             |
| Local service   | Your HTTP application on the publisher's computer.                  |
| Target          | The local HTTP URL the publisher uses to reach the local service.   |
| Tunnel          | One `tnl publish` or `tnl dev` invocation and its lifecycle.        |
| Project         | The selected directory, configuration, and Git worktree.            |
| Project service | A named local service with optional project-setting overrides.      |
| Worktree label  | A stable DNS-safe label derived from the worktree and client state. |

## routes

| Term            | Meaning                                                                                         |
| --------------- | ----------------------------------------------------------------------------------------------- |
| Route           | A stored mapping from a public hostname to a target, policy, and state.                         |
| Route session   | One publisher's server-side use of a route.                                                     |
| Route version   | The increasing number assigned to each continuous publishing run.                               |
| Ephemeral route | A route intended to expire after its tunnel stops.                                              |
| Enabled         | A stored route that is not suspended or deleted.                                                |
| Routable        | A route version with its certificate and enough ready publisher connections to accept visitors. |
| IP policy       | The rule controlling which visitor source addresses may use a route.                            |
| Route TLS       | The visitor's TLS connection, which terminates in the publisher.                                |

## teams and domains

| Term                      | Meaning                                                               |
| ------------------------- | --------------------------------------------------------------------- |
| Team                      | The ownership and authorization boundary for domains and routes.      |
| Personal team             | The permanent single-owner team created for an identity.              |
| Organization team         | A team created for collaboration.                                     |
| Membership                | An identity's relationship to a team, including role and member slug. |
| Member slug               | An immutable team-unique DNS label chosen for a membership.           |
| Member namespace          | A complete hostname built from a membership and team domain.          |
| Managed deployment domain | A server-controlled domain used to create member namespaces.          |
| Claimed domain            | A domain assigned to one team after DNS verification.                 |
| Team domain               | A managed deployment domain or claimed domain available to one team.  |
| Shared route              | A team-owned route outside individual member namespaces.              |

## server roles

| Term           | Meaning                                                                                     |
| -------------- | ------------------------------------------------------------------------------------------- |
| tnl server     | The deployed system, including control, ingress, relays, and PostgreSQL.                    |
| `tnld` process | One daemon process configured with a server role.                                           |
| Control        | The stateful role that stores state and coordinates the server.                             |
| Ingress        | The stateless role that accepts visitors, applies policy, and selects a relay.              |
| Relay          | The stateless role that holds publisher connections and visitor streams.                    |
| Relay service  | Interchangeable relay processes behind one stable relay address and failure boundary.       |
| Standalone     | A role that composes control, ingress, and two logical relay services in one process.       |
| Authority API  | The API that owns authentication, identities, teams, memberships, invitations, and domains. |

## connections and coordination

| Term                 | Meaning                                                                          |
| -------------------- | -------------------------------------------------------------------------------- |
| Publisher connection | A long-lived multiplexed connection from a publisher to a relay.                 |
| Connection slot      | One of the two publisher connections maintained by a route session.              |
| Connected relay      | The relay process currently holding a publisher connection.                      |
| Visitor connection   | One public TCP connection from a visitor to a route hostname.                    |
| Visitor stream       | One multiplexed stream carrying a visitor connection through a relay.            |
| Transport            | QUIC or TLS/TCP with yamux, used for a publisher connection.                     |
| Lease                | Control's time-limited permission for an ingress or relay process to serve work. |
| Process run ID       | A new identifier generated whenever an ingress or relay process starts.          |
| Draining             | Rejecting new work while existing connections finish until a deadline.           |

## addresses and security

| Term                        | Meaning                                                            |
| --------------------------- | ------------------------------------------------------------------ |
| Control URL                 | The HTTPS origin clients use for the control API.                  |
| Server domain               | The infrastructure DNS suffix for control, ingress, and relay.     |
| Ingress address             | The public address that sends visitors to ingress processes.       |
| Relay address               | The stable public hostname and port used by publishers.            |
| Internal relay address      | The private hostname and port ingress uses to reach a relay.       |
| Cluster authentication      | Authentication among split control, ingress, and relay processes.  |
| Storage key                 | The key control uses to encrypt recoverable secrets in PostgreSQL. |
| Relay transport certificate | The WebPKI certificate used by one relay service.                  |
