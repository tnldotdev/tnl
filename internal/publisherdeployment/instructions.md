# generated publisher deployment

Commit this directory with your project configuration. Run `tnl generate --check`
from the project to check every owned artifact without rewriting it. If you use
a custom output directory, pass the same `--output-dir` to generation and checks.

For each AWS publisher in `manifest.json`, the manifest names a group stack
template and a `.parameters.example.json` file. Copy the example to a separately
named actual parameter file; replace every `REQUIRED` entry before deployment.
Generation never owns that actual file. Examples contain public identifiers and
references only. Never put signing keys or identity JSON in parameter files.

Bootstrap supplies ControlURL, ProjectKey, Group, TeamID, PublisherGroupID,
DeploymentID, TemplateSHA256 and every replica's instance, publisher identity ID,
Secrets Manager ARN and pinned version. The manifest records exact per-replica
parameter names. Preserve DeploymentID and surviving replica identities across
updates; their EFS paths are `/tnl/DEPLOYMENT_ID/replica-N`.

The template injects nonsecret deployment/provider/replica/image/template metadata
into the publisher process. A signed runtime observation labels it
`publisher_reported`; it is not AWS attestation. Bootstrap being prepared does not
mean a publisher has run, and observed runtime metadata does not prove readiness.

Customer deployment settings include an existing VPC and task subnets, a
digest-pinned publicly pullable image, names, CPU/memory, architecture, logging,
KMS keys, permissions boundaries and optional existing compute resources. For EFS,
provide MountSubnetCount and MountSubnet1 through that count: exactly one subnet
per distinct AZ covering the task AZs.
The stack always creates encrypted retained Regional EFS, private access points,
and retained mount targets. Select one mount subnet per task AZ; clear only unused
MountSubnet entries.
The template does not discover subnets or change customer-owned resource policy.

Deploy with your reviewed CloudFormation workflow. Named IAM roles, including
those derived from ResourcePrefix, require CAPABILITY_NAMED_IAM; otherwise use
CAPABILITY_IAM for generated roles. Templates exceeding 51,200 bytes require an
S3 TemplateURL (or your tool's template_url), preserving their exact bytes.
The supported 1–8 replica range stays within template count and S3 size limits;
account vCPU and other service quotas still apply.

Each service runs one independent publisher without rolling surge. `/state`
remains task-local; `/identity` is retained private EFS state. Set a replica's
DesiredCount to zero before revoking or replacing its identity. Stack removal
retains EFS, access points, mount targets, their security groups and managed log groups. ECS RUNNING alone does not
prove successful target or visitor traffic.

`tnl generate` makes no control or AWS calls and never applies infrastructure.
Do not edit manifest-owned files. Keep custom templates alongside them under
different names. See the parameter descriptions in the generated template and
the [publisher deployment reference](https://github.com/tnldotdev/tnl/blob/main/deploy/publishers/readme.md)
for the complete network, role, KMS and lifecycle contract.
