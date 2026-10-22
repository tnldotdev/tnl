# role organization plan

place implementation with the role that owns its authority and lifetime. the
companion [domain boundaries plan](domain-boundaries-plan.md) defines the values
and transitions that those owners must preserve.

## accepted scope

- commands own input, process composition, and presentation. reusable operations
  live with publisher, connector, control, ingress, or relay.
- publisher owns serving, target forwarding, app registration, local process/API,
  signing identity, groups, integration URLs, and installation. its serving runtime
  does not depend on app or installed-process composition.
- connector owns visitor selection, connection operations, native owner lifetime,
  workload access, and kubeconfig. it does not depend on publisher serving or
  control persistence.
- control owns public, authority, and internal APIs, PostgreSQL, certificate and
  DNS work, identity providers, and maintenance. ingress and relay consume control
  contracts without importing its persistence implementation.
- shared client operations own authentication, state, team selection, project
  evaluation, initialization, and installed-job supervision. shared transport,
  policy, security, naming, observation, and failures remain below runtime owners.
- keep one generated package per HTTP contract under its serving owner. keep
  contract fragments, generators, embeddings, SDK bindings, fixtures, and checks
  with their source; remove obsolete packages and forwarding facades.
- align package declarations, configuration, wire fields, stored records, CLI,
  SDKs, Action, and website consumers with the same plain terms. services and
  public URLs retain their distinct records and lifecycles.
- use operation-focused files before adding packages. preserve useful assertions
  when removing overlap, and keep test tiers and selectors meaningful.
- keep maintainer guides short: explain hard-to-discover reasons, rules, and
  setup, then link to source. put execution history and check results in the PR.

see [architecture](architecture.md) for current ownership and
[contributing](../../contributing.md) for generation and validation commands.
