# publisher infrastructure templates

run a named publisher group near its targets with [`fargate.yaml`](fargate.yaml).
ECS replaces a failed task using the same replica identity, pending certificate
keys and installed certificates. the publisher uses the same filesystem store
as local development:

| directory   | contents                                                                              | storage                    |
| ----------- | ------------------------------------------------------------------------------------- | -------------------------- |
| `/identity` | signing identity, pending keys/CSRs, staged/current certificates and renewal metadata | private EFS access point   |
| `/state`    | runtime SQLite, its wrapping key, local events and caches                             | disposable task filesystem |

the template creates an ECS cluster, one single-replica service, separate execution
and task roles, a retained replica-specific EFS access point and a log group. it
uses an existing encrypted Regional EFS filesystem and a digest-pinned image
containing `tnl`. the publisher uses ordinary file operations; it needs no AWS
storage client or object-store checkpoint protocol.

## keep declarations in git

commit the group and its address targets in the application's `tnl.config.ts`:

```ts
import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig({
  team: "shop",
  publishers: {
    production: { description: "services in the production VPC" },
  },
  services: {
    orders: {
      publisher: "production",
      protocol: "postgres",
      target: {
        type: "address",
        address: "orders.internal:5432",
        tls: { caFile: "certs/database-ca.pem", serverName: "orders.internal" },
      },
      access: { team: true },
    },
  },
});
```

run `tnl config check`, then `tnl apply`. record its project key. group declarations
accept optional `description`, `domain` and `public` settings; `public` defaults
to false. infrastructure owns replicas, placement, storage and network rules.
development startup reports local listeners without applying remote changes.
hosted and self-hosted control use the same assignments and authorization boundary;
see [applied project boundaries](../../docs/maintainers/applied-projects.md).

## provision one replica identity

on an operator machine signed in as a manager for the project's team, choose a
new private output path outside the repository:

```console
tnl publisher provision --server "$CONTROL_URL" --project-key "$PROJECT_KEY" --team shop --group production --instance replica-1 --output-file "$IDENTITY_FILE"
```

provision creates and redeems a one-member enrollment, verifies the key with
control, and writes a mode-0600 file without replacing an existing path. its
protected pending key makes retries recover the same member after a lost response.
the bounded JSON contains the canonical control URL, team/project/group/member/key
identifiers, instance name and signing key. it contains no person session, target,
enrollment secret or runtime lease. output contains only public identifiers and
the file path.

store that file as a replica-private Secrets Manager `SecretString`:

```console
aws secretsmanager create-secret --name tnl/shop/production/replica-1 --secret-string "file://$IDENTITY_FILE" --query '{arn:ARN,version:VersionId}' --output json
```

record the returned ARN and version ID as infrastructure inputs. an existing
secret can receive the same private file with `put-secret-value`; pin the returned
version. ECS injects the JSON as `TNL_GROUP_IDENTITY`, which `tnl` consumes and
clears before workers start. a mounted private file can instead use
`--identity-file /run/tnl/replica.json`. each independent replica needs its own
identity, instance name and access point.

## deploy the service

use your reviewed CloudFormation workflow with `CAPABILITY_IAM`. supply:

- `ControlURL`: the HTTPS control origin without a trailing slash.
- `ProjectKey`, `Group`, `Instance`: the applied project, publisher selector and
  provisioned replica instance. `local` is reserved.
- `IdentitySecretArn`, `IdentitySecretVersion`: the private bootstrap secret and
  explicit version. replacements reuse this member without enrollment.
- `IdentityKMSKeyArn`: the customer-managed key if the bootstrap secret uses one;
  otherwise leave empty. permit the execution role in that key's policy.
- `IdentityFileSystemId`: an existing encrypted Regional EFS filesystem in the
  task VPC. provide mount targets reachable from the selected subnets. permit
  TCP 2049 from the task security groups to the mount-target security groups.
  the filesystem policy must allow IAM-authorized mounts through this access
  point; filesystem creation, backup and mount-target management belong to your
  infrastructure.
- `Subnets`, `SecurityGroupIds`: private subnets and task security groups. permit
  DNS, control HTTPS, advertised relay TCP/UDP ports, EFS and assigned targets.
  image pulls, Secrets Manager and CloudWatch Logs need appropriate outbound
  connectivity. target security groups separately permit publisher connections.
- `PublisherImage`: a publicly pullable `@sha256:` reference. the image contains
  `/usr/local/bin/tnl` and private `/state` owned by UID/GID 65532. the template
  runs that nonroot user with Linux capabilities dropped.
- `DesiredCount`: `1` runs this replica; `0` stops it. deploy another stack and
  identity for an additional replica.

the execution role can read the selected secret/version and write operational
logs. the task role can mount and write only the selected EFS filesystem through
its replica-specific access point over encrypted transport. the access point
enforces UID/GID 65532 and a mode-0700 root beneath `/tnl/STACK_NAME`. only that
volume is mounted; runtime SQLite remains local. the command contains no secret:

```console
tnl --no-config publisher serve --server CONTROL_URL --project-key PROJECT_KEY --group production --state-dir /state --identity-dir /identity --instance replica-1
```

## replacement and durable ownership

a new task starts with empty `/state`, proves its signing key and current group
membership to control, then uses the existing identity files on `/identity`.
the same member and certificate state survive a crash, image update, subnet
change or scale-to-zero/one cycle. invalid or revoked bootstrap input fails
without fallback to another identity or enrollment. the durable directory can
also restore the signing identity without bootstrap input when the control URL,
project, selector and instance are supplied.

identity records are scoped to the control and immutable publisher identity.
certificate records include the exact team and approved plan. complete records
are written to private temporary files, synced, atomically replaced and synced
again before external issuance or installation. a pending key survives a crash
without becoming another CSR; staged material remains recoverable before its
installation acknowledgement. compatible sibling services share only their own
replica's wildcard material. control never stores publisher TLS private keys.

the publisher holds an advisory writer lock on the durable filesystem throughout
the group's lifetime. replacement waits for the previous owner; independent
runtime directories cannot bypass this lock. the filesystem must support the
required atomic replacement, sync and advisory-lock semantics, including NFSv4
locking for EFS. all writers for a replica must use the same durable directory.
control leases continue to enforce current authorization independently.

the service keeps desired count at most one, `MinimumHealthyPercent=0`,
`MaximumPercent=100` and availability-zone rebalancing disabled. these settings
avoid a rolling surge with a shared member. `StopTimeout=120` gives the old
process time to drain. existing visitor connections end during replacement and
are never replayed. another independently enrolled replica in the group provides
capacity while this one is replaced.

temporary write/sync failures prevent new issuance or installation from relying
on unsaved material. an existing valid certificate remains available during
retryable renewal failures. invalid, mismatched or missing required certificate
files fail instead of silently replacing the keys. control records when issuance
first starts; restore the replica's valid identity directory when recovery fails.
back up that directory using your filesystem's normal backup facilities.

keep SQLite and its WAL on the task filesystem. only the durable identity files
and their writer locks belong on EFS. local development defaults to `identities`
beneath the normal state directory and uses this same implementation.

check `tnl status --scope=server`, then use `tnl connect orders` and a native
database client. ECS `RUNNING` alone does not establish target reachability or
successful visitor traffic.

## rotate or remove a replica

1. set `DesiredCount=0` and wait for its tasks to reach `STOPPED`.
2. revoke the old member through control using its project, group and publisher
   identity from server status.
3. provision a fresh instance name and identity, then store its private JSON in
   the replica's secret.
4. update `Instance` and `IdentitySecretVersion`, retain the filesystem inputs,
   and set `DesiredCount=1`. check revision, health and visitor traffic.

stopping ECS or deleting a secret does not revoke the identity. the access point
and log group are retained when the stack is removed; the external filesystem
and its data remain owned by your infrastructure. remove retired identity files
and retained resources through that workflow after no publisher depends on them.

## validate locally

```console
mise exec -- task deploy:publishers:check
mise exec -- task go:test:publisher-identity
mise exec -- task go:test:publisher-state
mise exec -- task go:test:integration:publisher-replacement
```

the template target runs Vitest, TypeScript, lint and pinned offline cfn-lint
checks. filesystem tests cover complete records, scope validation, unsafe paths,
uncertain writes, independent runtime directories and a killed lock-holder.
integration targets own disposable PostgreSQL. the Linux CLI workflow runs real
control, ingress, relays and publisher workers, substituting the external CA/DNS
boundary. it deletes runtime state during issuance and after installation and
checks the same member, issuance and real visitor traffic. these checks do not
deploy AWS resources or establish live EFS/VPC behavior.
