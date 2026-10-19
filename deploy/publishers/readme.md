# generated aws publishers

Generate a CloudFormation stack for a named publisher group, then deploy it with
your infrastructure workflow. Keep only structural capacity in project config:

```yaml
version: 1
tnl:
  publishers:
    production:
      aws: { replicas: 2 }
  services:
    orders:
      publisher: production
      protocol: postgres
      target: { type: address, address: "orders.internal:5432", tls: {} }
      access: { team: true }
```

TypeScript uses the same `publishers.production.aws` object. An empty `aws: {}`
defaults to one replica; the supported range is 1–8. Omit `aws` for groups whose
infrastructure you manage separately. `local` remains reserved.

```console
tnl generate
tnl generate --check
tnl generate --output-dir infrastructure/generated
tnl generate --check --output-dir infrastructure/generated
```

The default output is relative to the selected project's root:

```text
.tnl/generated/manifest.json
.tnl/generated/readme.md
.tnl/generated/aws/production.yaml
.tnl/generated/aws/production.parameters.example.json
```

Commit these files. Ignore only `/.tnl/local/`, whose worktree metadata remains
local. `--output-dir` also accepts an absolute directory. Use a real directory,
without symlink components. The command rejects symlinks and conflicting unowned
files. It preserves unrelated custom templates and actual parameter files.
When a group is removed, generation removes its old manifest-owned files only
if they still match their recorded hashes; move edited retired files first.

Generation evaluates trusted project config and reads the local Git origin and
configuration path. It uses the same stable source identity as `tnl apply`,
independent of Git branch, checkout directory, HEAD, or installation salt. It
opens no session or client database and makes no control, AWS, or network calls.
TypeScript config is executable project code: keep its capacity declaration
independent of local paths, time, environment, or network for repeatable output.
`--check` reads all expected bytes, including the manifest ownership list; it
creates no output directories or temporary artifacts. Normal ephemeral
TypeScript evaluation is still allowed.

`tnl apply` reconciles services and group policy with control. AWS capacity is
excluded from its wire declaration and configuration hash, so changing replica
count does not restart assigned remote apps through apply. `tnl generate` does
not provision identities or apply infrastructure. There is no deploy flag.

## one group stack

Each replica is a separate single-task ECS Fargate service with its own pinned
signing identity secret, execution role, task role, log group and retained EFS
access point. Logical IDs use replica numbers rather than mutable group or
physical names. Scaling preserves `replica-1` through `replica-N`; adding a
replica appends a new independent identity. Scaling down removes services but
retains their access points and managed log groups.

| directory   | contents                                                                              | storage                    |
| ----------- | ------------------------------------------------------------------------------------- | -------------------------- |
| `/identity` | signing identity, pending keys/CSRs, staged/current certificates and renewal metadata | private EFS access point   |
| `/state`    | runtime SQLite, wrapping key, local events and caches                                 | disposable task filesystem |

The stack always creates encrypted **Regional** EFS, with backups enabled,
retention on removal/replacement, and a private root at
`/tnl/DEPLOYMENT_ID/replica-N`. Access points enforce UID/GID 65532 and mode 0700.
The task role permits only IAM-authorized, encrypted mounts and writes through
that replica's access point; it cannot read Secrets Manager or mount as root.
The filesystem denies insecure and anonymous client access. EFS retains identity
files across task replacement; the publisher's existing advisory writer lock
and atomic file store provide the durable ownership boundary.

Every task launch receives `TNL_GROUP_IDENTITY` from an existing Secrets Manager
container at an explicit version. Bootstrap owns those containers and their JSON;
the template contains references only. The publisher consumes and clears the
injected JSON before starting workers. A stale or revoked identity fails closed.
The runtime command remains:

```console
tnl --no-config publisher serve --server CONTROL_URL --project-key PROJECT_KEY --group GROUP --state-dir /state --instance INSTANCE --identity-dir /identity
```

The image must provide `/usr/local/bin/tnl` and writable private `/state` owned by 65532. It runs nonroot with all Linux capabilities dropped, no inbound ports,
execute-command disabled, and a 120-second shutdown timeout. Desired count is
zero or one per service. Minimum healthy percent 0, maximum percent 100, and
disabled AZ rebalancing prevent a rolling surge using the same signing identity.
Connections end during replacement and are never replayed. Independent replicas
provide capacity while another replica is replaced.

## deployment parameters

Copy the generated `.parameters.example.json` to a separately named, reviewed
parameter file. Generation updates the example, never an actual parameter file.
The example is AWS's `[{"ParameterKey":"...","ParameterValue":"..."}]` shape.
`REQUIRED` entries must be resolved before deployment. The manifest's SHA-256
values identify exact artifact bytes; templates are deterministic YAML.
Do not manually edit manifest-owned files.

### bootstrap identity contract

| parameter                       | value                                                                                                     |
| ------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `ControlURL`                    | canonical HTTPS control origin, no trailing slash                                                         |
| `ProjectKey`                    | source project key, also present in the manifest                                                          |
| `Group`                         | configuration group selector, also the manifest publisher `name`                                          |
| `TeamID`                        | actual immutable team ID, resolved during bootstrap                                                       |
| `PublisherGroupID`              | actual immutable group ID, resolved during bootstrap                                                      |
| `DeploymentID`                  | immutable, unique lowercase deployment ID, 1–48 characters; preserve for the lifetime of these identities |
| `TemplateSHA256`                | exact template hash from the manifest; caller-supplied metadata, not AWS attestation                      |
| `ReplicaNInstance`              | exact provisioned instance name from bootstrap                                                            |
| `ReplicaNPublisherIdentityID`   | public identity ID returned by bootstrap                                                                  |
| `ReplicaNIdentitySecretArn`     | ARN of that replica's existing private identity JSON secret                                               |
| `ReplicaNIdentitySecretVersion` | pinned Secrets Manager version ID, 32–64 characters                                                       |

The template rejects repeated instance names, publisher IDs, or secret ARNs
within one stack. Bootstrap must also verify the JSON identities and scope;
CloudFormation cannot inspect private JSON. Each secret must contain the exact
canonical control/team/project/group/member/instance identity provisioned by
control, never a person session, enrollment key, database credential or target.
Team/group/publisher ID parameters are public metadata and outputs; the signed
identity JSON remains authoritative at runtime.

Template version 2 supplies deployment metadata as nonsecret `TNL_DEPLOYMENT_*`
environment values. The running publisher binds its report into the existing
signed runtime lease. Control shows it as `publisher_reported`, with its actual
publisher/team/group identity and control receipt times. The report is not AWS
attestation or a health check. Bootstrap's `prepared` result remains distinct from
an actual runtime observation. See [deployment provenance](../../docs/maintainers/publisher-provenance.md)
for the complete field and environment contract.

See [the bootstrap API contract](../../docs/maintainers/publisher-generation.md)
for exported Go types and stale-artifact validation.

### networking and storage

| parameter                          | behavior                                                                                             |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `VpcId`, `Subnets`                 | existing VPC and task subnet IDs; no VPC or subnet creation                                          |
| `ExistingPublisherSecurityGroupId` | optional existing primary task group; otherwise create no-inbound, standard IPv4/IPv6-outbound group |
| `AdditionalSecurityGroup1` … `4`   | optional additional task groups; maximum five including primary                                      |
| `AssignPublicIp`                   | `DISABLED` by default; `ENABLED` requires appropriate public routing                                 |
| `MountSubnetCount`                 | 1–6 retained mount targets, default 2                                                                |
| `MountSubnet1` … `6`               | fill exactly the selected count with **one subnet per distinct AZ**, covering all task AZs           |
| `FileSystemKMSKeyArn`              | optional customer key for EFS; empty uses the EFS default key                                        |

There are no subnet lookups or custom Lambda resources. CloudFormation requires
every selected mount subnet; operators must select one per AZ, even when task
subnets include several in one AZ. The new EFS group permits TCP 2049 only from
the primary task group. Services depend on their created mount targets through
conditional resource tags. Existing security groups keep their current rules. Targets
separately permit publisher traffic. Tasks need DNS, control HTTPS, advertised
relay TCP/UDP ports, targets, EFS, the image registry, Secrets Manager and logs
through NAT or appropriate endpoints. The template does not claim to establish
live network reachability.

### names, roles, logs and runtime

| parameter                                                           | behavior                                                                                         |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `ResourcePrefix`                                                    | optional 1–32 character physical-name prefix; empty uses CloudFormation names                    |
| `ClusterName`, `PublisherSecurityGroupName`, `EFSSecurityGroupName` | individual overrides for new resources                                                           |
| `ExistingClusterArn`                                                | existing cluster; stack creates only its services                                                |
| `ReplicaNServiceName`, `ReplicaNTaskFamily`, `ReplicaNLogGroupName` | individual physical-name overrides                                                               |
| `ReplicaNExecutionRoleName`, `ReplicaNTaskRoleName`                 | individual new role names, maximum 64 characters                                                 |
| `ReplicaNExistingExecutionRoleArn`, `ReplicaNExistingTaskRoleArn`   | customer-owned roles with equivalent replica-scoped policies; stack does not alter them          |
| `PermissionsBoundaryArn`                                            | boundary applied to all newly created roles                                                      |
| `ReplicaNExistingLogGroupName`                                      | customer-owned log group; retention and KMS settings remain external                             |
| `LogRetentionDays`                                                  | allowed CloudWatch retention, default 30 days, new groups only                                   |
| `LogsKMSKeyArn`                                                     | optional key for new log groups                                                                  |
| `ReplicaNIdentityKMSKeyArn`                                         | optional key for the corresponding identity secret                                               |
| `PublisherImage`                                                    | publicly pullable `registry/path@sha256:...`; mutable tags rejected                              |
| `TaskCPU`, `TaskMemory`                                             | default 256 units/512 MiB; rules enforce Fargate's supported combinations for 256–4096 CPU units |
| `CPUArchitecture`                                                   | `X86_64` (default) or `ARM64`; match the image digest                                            |
| `PlatformVersion`                                                   | Linux `1.4.0` (default) or `LATEST`                                                              |
| `ReplicaNDesiredCount`                                              | `1` (default) to run, `0` to stop without removing identity state                                |

Individual names override the prefix. Existing-resource inputs override managed
resource creation; those resources never become stack-owned. Physical-name
changes can replace managed resources, but do not change logical IDs or EFS
identity paths. Keep `DeploymentID` and replica identity inputs stable across
renames and updates. A nonempty prefix or explicit IAM role name requires
`CAPABILITY_NAMED_IAM`; unnamed generated roles require `CAPABILITY_IAM`.

The execution role reads only its secret and pinned version and writes only its
log group's streams. With a customer secret key, decrypt is restricted by
`kms:ViaService=secretsmanager.REGION.URL_SUFFIX` and
`kms:EncryptionContext:SecretARN=SECRET_ARN`. Permit that execution role in the
key policy. Logs encryption belongs to `logs.REGION.URL_SUFFIX`, with
`kms:EncryptionContext:aws:logs:arn` equal to the log group ARN **without** `:*`;
permit the regional Logs service in the key policy. EFS encryption belongs to
the EFS service, using `kms:ViaService=elasticfilesystem.REGION.URL_SUFFIX` and
`kms:EncryptionContext:aws:elasticfilesystem:fs-id` for the filesystem. The
deployment principal needs the relevant key/grant permissions. Task roles need
no KMS decrypt for logs or EFS. Keys and key policies remain customer-owned.
All constructed resource ARNs use `AWS::Partition`; regional service endpoints
use `AWS::URLSuffix`.

Apply customer tags on the stack. Explicit supported resource tags include
deployment, project, team and group IDs; ECS propagates service tags to tasks.
The output contract has `OutputSchemaVersion=1`, `TemplateVersion=1`,
`TemplateSHA256`, identity metadata, `ClusterArn`, `PublisherSecurityGroupId`,
`IdentityFileSystemId`, and per-replica service/task-definition/log/access-point,
execution/task role, publisher ID and secret ARN/version references. Outputs
contain no private key or secret JSON.

## limits, lifecycle and validation

Templates are bounded below CloudFormation's 200 parameters, 500 resources,
200 outputs and 1 MiB S3 template limit at eight replicas. Even small generated
stacks can exceed the 51,200-byte inline template-body limit. Use an external
S3 `template_url`/`TemplateURL` in that case. Deployment tooling must preserve
the exact hashed bytes. Account Fargate vCPU/service, EFS access-point, IAM and
network quotas still apply; request account quota increases separately.

Before retiring a replica, stop its service and wait for tasks to stop, then
revoke its publisher identity in control. Removing ECS or a secret does not
revoke identity. Keep retained EFS data and access points until no publisher
uses them. Recover the same replica with its original signing identity and
DeploymentID; deliberately replacing an identity requires a separately reviewed
state transition rather than copying another replica's JSON into its secret.
The filesystem, access points, mount targets and stack-created security groups
are retained on removal and replacement. The security groups remain because the
retained mount targets and their NFS rule depend on them. Remove retained resources
explicitly only after retiring their identities and recovering any needed data.
Customer-owned resources remain
customer-owned. ECS `RUNNING` alone does not prove successful visitor traffic.

[`fargate.yaml`](fargate.yaml) is a generated, reviewed two-replica fixture, not a
second template source. `internal/publisherdeployment` owns the renderer;
`task generate` refreshes this fixture and its example manifest/parameters.
The fixture manifest describes the normal generated directory layout, not these
renamed fixture paths. Use `tnl generate` for a deployable project bundle.

```console
mise exec -- task generate
mise exec -- task deploy:publishers:check
```

The check runs deterministic and read-only Go tests, typed template tests, and
pinned offline cfn-lint for the full template and explicit new/existing-resource
branches. Runtime durable identity and replacement coverage remains in
`task go:test:publisher-identity`, `task go:test:publisher-state` and
`task go:test:integration:publisher-replacement`. These checks do not deploy AWS
resources or establish live EFS/VPC behavior.
