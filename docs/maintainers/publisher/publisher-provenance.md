# publisher deployment provenance

Control can show which deployment a running group publisher reports, alongside
its existing runtime lease and control-observed egress. Bootstrap still reports
`prepared`: creating a signing identity or secret never records a runtime or
deployment observation.

The authoritative wire source is `api/control/public/v1/openapi.yaml`:

- `PublisherRuntimeRequest.deployment` is an optional `PublisherDeploymentReport`.
- `PublisherRuntimeStatus.deployment` is an optional `PublisherDeploymentObservation`.
- The existing `POST /v1/publisher-runtime` start/renew/stop lifecycle writes the
  observation. Inspect, enrollment, bootstrap and key verification do not.
- The existing authenticated publisher inventory and applied-project responses
  expose runtime status. `tnl publisher list`, project `tnl status`, and bootstrap's
  `observed_members` use those responses. Public project metadata excludes it.

## reported fields

All report fields are required together. They contain identifiers and bounded
descriptive values, never credentials, target addresses or arbitrary labels.

| field              | bound and meaning                                                                                                      |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| `deployment_id`    | 1–48 lowercase letters, digits and hyphens; starts with a letter or digit; the stable bootstrap `DeploymentID`         |
| `provider`         | `aws`                                                                                                                  |
| `replica_key`      | 1–32 character lowercase service label; generated slots are `replica-1` through `replica-N`                            |
| `instance`         | the 1–32 character instance selected by the publisher's existing identity input                                        |
| `image`            | at most 512 characters; registry/repository plus `@sha256:` and 64 lowercase hex digits; no scheme, tag or credentials |
| `software_version` | at most 64 ASCII letters, digits, `.`, `+`, `_`, `-`; starts with a letter or digit                                    |
| `template_version` | the same version characters, at most 32                                                                                |
| `template_sha256`  | exactly 64 lowercase hex digits                                                                                        |

The observation wraps these fields under `report`:

```json
{
  "report": {
    "deployment_id": "aws-example",
    "provider": "aws",
    "replica_key": "replica-1",
    "instance": "aws-instance",
    "image": "ghcr.io/tnldotdev/tnl@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "software_version": "v1.2.3",
    "template_version": "2",
    "template_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  },
  "group_id": "pgrp_example",
  "evidence": "publisher_reported",
  "first_observed_at": "2026-10-19T12:00:00Z",
  "observed_at": "2026-10-19T12:00:05Z"
}
```

`group_id` comes from control's current publisher membership. The surrounding
runtime supplies its authenticated `publisher_identity_id` and `team_id`.
Requests cannot supply these as deployment fields. Control verifies the active
publisher, its exact group and enrolled signing key before recording anything.
Non-group publishers cannot submit deployment metadata.

Both timestamps are control receipt times. `first_observed_at` survives process
replacement; `observed_at` follows the latest accepted start, renewal or stop.
The report survives lease expiry, stop and revocation as historical evidence.
Use the surrounding runtime's `active`, lease and stop fields to distinguish a
current process. These fields do not imply visitor readiness or target health.

## signature and state boundary

`internal/policy/publisherprovenance` validates the generated API type. Its `Digest`
hashes this canonical JSON array with SHA-256:

```text
["tnl publisher deployment v1", deployment_id, provider, replica_key,
 instance, image, software_version, template_version, template_sha256]
```

`publisheridentity.RuntimeScope` binds that digest, when present, into the
existing one-use runtime assertion along with scope, action, process run ID and
epoch. Adding, removing or changing metadata invalidates the original signature.
`publisherruntime.Owner` copies the report once and reuses it for its existing
inspect/start/renew/stop calls; it adds no worker or observation loop.

The latest report is stored in the existing `control.publisher_runtimes` row:
`deployment_report`, `deployment_group_id`, `deployment_first_observed_at`.
`internal/control/state/queries/publisher_runtimes.sql` owns its sqlc queries. A
foreign key binds the recorded group to the publisher member. A unique index
reserves `(group_id, deployment_id, replica_key)` to one publisher identity,
including while stopped or revoked. No deployment management table or cloud
reconciliation loop is added.

Within a process run the entire report is immutable, including during lost-start
recovery. A new process may change image/software/template values, but cannot
change or remove the first observed deployment/provider/replica/instance binding.
Independent replicas need independent keys. Process replacement reuses the
original signing identity. A newly provisioned identity needs a new binding;
there is no automatic takeover of an observed slot.

The fresh PostgreSQL baseline identity is now
`tnl-control-fresh-v1-relay-connector-peers`.
This is part of the approved fresh-database rewrite, not an in-place migration.

## generated process environment

Template version 2 injects exactly these nonsecret metadata inputs:

| environment variable              | source                                   |
| --------------------------------- | ---------------------------------------- |
| `TNL_DEPLOYMENT_ID`               | bootstrap `DeploymentID` parameter       |
| `TNL_DEPLOYMENT_PROVIDER`         | literal `aws`                            |
| `TNL_DEPLOYMENT_REPLICA_KEY`      | manifest replica key                     |
| `TNL_DEPLOYMENT_IMAGE`            | digest-pinned `PublisherImage` parameter |
| `TNL_DEPLOYMENT_TEMPLATE_VERSION` | renderer `TemplateVersion`               |
| `TNL_DEPLOYMENT_TEMPLATE_SHA256`  | bootstrap `TemplateSHA256` parameter     |

`publisherprovenance.ReadEnvironment(lookup, instance, softwareVersion)` is the
read-only adapter. The CLI supplies its selected instance and `buildinfo.Version`;
there is no tenant or software-version environment override. Absent metadata
keeps the ordinary runtime behavior. Partial, empty or invalid metadata fails
before identity setup. For a supervised publisher, configure the environment
on the process that actually runs it; these values are not saved in job records.

`grouppublisher.Runtime.Deployment` passes the typed report to the optional final
argument of `publisherruntime.New`. Other callers continue without a report.
This is also the metadata boundary available to optional OTel integration. OTLP
exporter configuration remains independent: this code adds no exporter, SDK,
hosted receiver, telemetry credentials or arbitrary resource-attribute parser.

## limits of the evidence

`publisher_reported` means control authenticated the publisher that sent the
report. It is not AWS attestation. A holder of that publisher's key can claim an
image, software version, template version/hash or an unused slot in its own
group. Control does not query AWS, inspect container images, or verify that the
reported template bytes were deployed. The first accepted report pins a binding;
it is not proof of an operator's deployment plan.

Bootstrap validates its generated manifest and emits expected nonsecret bindings
and template version/hash. Its prepared receipt and a signed runtime observation
are separate facts. Consumers may compare them; they must label the runtime
values as reported and must not turn either fact into cloud permissions or a
claim that a deployment is healthy.

## validation

```console
mise exec -- task go:test:publisher-provenance
mise exec -- task go:test:integration:publisher-egress
mise exec -- task deploy:publishers:check
mise exec -- task go:test:aws-bootstrap
mise exec -- task go:test:integration:aws-bootstrap
```

Generation runs the OpenAPI generators before internal generators that compile
those models. After committing source and generated changes, run
`mise exec -- task generate-check` to compare the complete generated surface.
