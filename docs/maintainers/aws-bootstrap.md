# publisher bootstrap boundaries

`tnl bootstrap production` prepares signing identities and pinned Secrets Manager
versions for one customer-owned deployment. `production` selects a publisher in
the current project configuration; its `aws` declaration selects the provider.

```console
tnl apply
tnl generate
tnl bootstrap production --deployment-file deploy/publishers/aws.json --output=json
```

The command uses the current tnl operator session and company authorization. It
checks the applied project key, source fingerprint, team and immutable group ID,
then validates the generated manifest against current configuration and artifact
bytes. AWS credentials use the SDK's standard chain; `--profile company` selects
a shared profile. STS must report the account in the customer deployment file.
`--region` is optional and must agree with that file.

## customer deployment input

Keep infrastructure choices in a customer-owned JSON file, separate from
`tnl.yml` and `.tnl/generated/`. A minimal file works before a VPC or subnet exists:

```json
{
  "schema_version": 1,
  "deployments": [
    {
      "name": "production-east",
      "publisher": "production",
      "account_id": "123456789012",
      "region": "us-east-1",
      "parameters": {
        "TaskCPU": "256",
        "TaskMemory": "512"
      },
      "identity_secrets": {
        "replica-1": {
          "name": "customer/production/replica-1",
          "kms_key_id": "alias/publisher-identities"
        }
      }
    }
  ]
}
```

`parameters` holds the customer's deployment settings from the generated template.
Bootstrap does not require network values or check their existence. Supply the
image digest, VPC, subnets and other deployment choices before running the
customer's infrastructure tool. Merge the command's `parameters` array into those
settings. Bootstrap-owned identity and scope parameter names cannot appear in the
customer parameters. Customer values are not copied into local receipts.

`--deployment production-east` selects among multiple deployments of the same
group. Keep the name stable across retries and updates. Account, region and
deployment name separate identities; a different operator's local installation
does not affect instance names. Replica keys come from the manifest. Adding a
replica retains every surviving slot's key, secret name and version. A group
selector rename preserves the immutable group binding.

Each secret override may set either `name` with optional `kms_key_id`, or
`existing_arn`. An existing container must be empty. Bootstrap preserves external
container ownership and does not change its tags or KMS configuration. To reuse a
previously provisioned identity instead, supply `existing_arn`, `existing_version`
and `publisher_identity_id` together. Its instance, key, current membership,
control origin, team, project and immutable group must match this deployment.
An invalid or revoked identity never falls back to enrollment.

For a customer KMS key, also supply its full key ARN in that replica's deployment
parameter, such as `Replica1IdentityKMSKeyArn`. An alias used to create a secret is not
an IAM resource ARN. Customer-managed execution roles need permission to read the
pinned secret version and decrypt it with that key.

## durable operation ownership

`internal/publisherprovision` owns the same group provisioning flow for
`publisher provision` and bootstrap. It saves a signing key before issuing or
redeeming enrollment, retains enrollment results, verifies current membership
with a signed control proof, and imports only the exact selected identity. Pending
provisioning keys do not expire. Lost enrollment replies redeem the original key;
control deduplicates that public key and rejects revoked members.

The fresh client-state baseline includes `publisher_provision_journal`. Entries
are append-only, revision-checked and encrypted with the existing wrapping key.
Their authenticated context binds the journal kind, deployment binding and
revision. Group records own signing keys and enrollment tokens. AWS records own
the control/team/project/group/source/account/region/deployment/slot tuple, random
ownership proof, stable request tokens and each completed transition.

Before enrollment, a new secret container receives a private random ownership
marker. An externally provisioned empty container receives the same kind of
marker as a separate, explicitly staged version. On response loss, bootstrap
describes only the exact selected resource and reads only its journal-pinned
version. A bootstrap-created container must have the exact name, ARN scope and
ownership tags, plus the matching private marker. Tags alone cannot authorize a
key write. Existing populated containers require explicit pinned identity input.

The identity is stored under another persisted `ClientRequestToken`, with its own
`tnl-<token>` version stage. Bootstrap does not move `AWSCURRENT`; generated ECS
bindings use the exact identity version. Before reporting `prepared`, bootstrap
reads that version back, compares the private key and immutable identity, and
checks current control membership. It never rotates a key to recover from a
missing key, secret, conflicting version or revoked identity.

Nonsecret intent and completion receipts live only in `.tnl/local/aws/`. Intent
receipts detect a missing journal even if the remote container has not been
created. A remote marker detects lost local state after container creation. Restore
the original protected client state to resume an interrupted operation. Receipts
are historical observations, not proof that a secret or grant remains valid.

## provider and output boundary

Only bootstrap loads AWS clients. Its provider interface contains STS caller
identity and Secrets Manager create, describe, get and put operations. There is
no CloudFormation, ECS, network, EFS or S3 deployment interface. The customer runs
deployment tooling after preparation. Bootstrap creates no backend permissions,
credentials broker or target allowlist changes.

SDK retries are bounded to three attempts inside a finite command context. All
work is synchronous and cancellation returns to the caller. Structured AWS codes
select authored IAM, credential, throttling, collision, version or availability
failures; provider response bodies never become CLI diagnostic text. Finite JSON
contains references and instructions, while human output uses the shared ASCII
renderer. The result includes only already-observed control runtime records for
the selected identities; it does not claim egress for tasks that have not run.

## verification

```console
mise exec -- task go:test:aws-bootstrap
mise exec -- task go:test:integration:aws-bootstrap
```

The local HTTPS fixture verifies real SDK SigV4 requests and permits only the
bounded provider operations. Tests cover lost replies, each journal transition,
foreign containers and keys, pinned versions, revocation, independent slots,
multiple deployments, lost state, structured failures and cancellation. The
integration target owns disposable PostgreSQL and uses real apply, enrollment,
signed verification, rename and revocation APIs alongside the AWS fixture.
