# run publishers on aws

Generate a CloudFormation stack to run `tnl` beside your private services. Each
replica gets its own Fargate service, signing identity, and persistent EFS directory.

You'll need a Git project with an `origin` remote, a tnl team you can manage, AWS
credentials, an existing VPC, and a published tnl image pinned by digest. The task
subnets need to reach your targets, tnl control and relays, EFS, the image registry,
Secrets Manager, and CloudWatch.
Use NAT or the appropriate service endpoints for private subnets. Publishers
connect outward to relays, so they need no inbound ports.

```text
your terminal       tnl control          aws
     |-- apply ---------->|              |
     |-- bootstrap ------>|              |
     |-- save identities --------------->| secrets manager
     |-- deploy template --------------->| fargate + efs
```

## generate the stack

In your project's `tnl.yml`, assign services to a publisher group:

```yaml
version: 1
tnl:
  team: studio
  services:
    orders:
      protocol: postgres
      target:
        type: address
        address: orders.internal:5432
        tls: {}
      access:
        team: true
      publisher_group: production
  publisher_groups:
    production:
      aws:
        replicas: 2
```

The target must support TLS with a certificate trusted by the publisher. The
replica count can be 1–8. From the project root, run:

```sh
tnl generate
tnl generate --check
```

Commit `.tnl/generated/` with your configuration. For `production`, it includes
`aws/production.yaml`, a storage policy, and an example parameter file.
`manifest.json` records their paths and hashes. Regenerate these files rather
than editing them. Generation makes no control or AWS calls.

## prepare the identities

Create `deploy/publisher/fargate/aws.json` in your project, replacing the account
and region with yours:

```json
{
  "schema_version": 1,
  "deployments": [
    {
      "name": "production-east",
      "publisher_group": "production",
      "account_id": "123456789012",
      "region": "us-east-1"
    }
  ]
}
```

Apply the service configuration, then prepare one identity secret per replica:

```sh
tnl apply --team studio
tnl bootstrap production --team studio --profile company --output json > bootstrap.json
```

Use your AWS profile, or omit `--profile` to use the normal AWS credential chain.
Bootstrap needs permission to create, read, and write its Secrets Manager secrets.
It stores the signing keys there and returns only IDs and secret references.
Keep its saved client state for retries, and keep `.tnl/local/` out of Git.

## fill the parameters and deploy

```sh
cp .tnl/generated/aws/production.parameters.example.json production.parameters.json
```

Replace matching entries in the copy with the `parameters` returned in
`bootstrap.json`, including the instance names. Then fill every remaining
`REQUIRED` value:

- `PublisherImage`: a publicly pullable `image@sha256:...` reference. Match
  `CPUArchitecture` to the image; the default is `X86_64`.
- `VpcId` and `Subnets`: the existing VPC and comma-separated task subnet IDs.
- `MountSubnetCount` and `MountSubnet1` through that count: one EFS mount subnet
  per distinct availability zone used by tasks. Leave unused entries empty.

The template describes optional sizing, names, existing resources, and KMS keys.
If you supply existing roles or customer-managed keys, give them the permissions
described there. Parameter files contain references, never private signing keys.

Upload the generated YAML unchanged to S3 and set `TEMPLATE_URL` to its HTTPS URL.
Using S3 avoids CloudFormation's 51,200-byte inline-template limit. For example,
with the AWS CLI configured for the same account and region:

```sh
aws cloudformation create-stack \
  --stack-name tnl-production \
  --template-url "$TEMPLATE_URL" \
  --parameters file://production.parameters.json \
  --stack-policy-body file://.tnl/generated/aws/production.storage-policy.json \
  --capabilities CAPABILITY_NAMED_IAM
aws cloudformation wait stack-create-complete --stack-name tnl-production
tnl status
```

The stack policy prevents updates from replacing identity storage. Keep it on
later updates. After deployment, check the publisher logs and connect to a service;
an ECS task marked `RUNNING` only tells you the container started.

## keep identities through updates

`/identity` is private EFS storage for signing keys and certificates. `/state` is
temporary task storage. Keep the same deployment name, `DeploymentID`, replica
identities, secret containers, EFS paths, and storage KMS key across replacements.
Each replica runs at most one task; its connections close while that task is replaced.

Save the fully resolved deployed parameters, including defaults and retired
replica slots. Before an update, compare them with the new parameters from a tnl
source checkout:

```sh
mise exec -- task deploy:publishers:storage-check \
  PREVIOUS=/absolute/path/deployed.parameters.json \
  NEXT=/absolute/path/next.parameters.json
```

Review the CloudFormation change set before applying it. To retire a replica,
set `ReplicaNDesiredCount` to `0`, wait for its task to stop, then revoke its
publisher identity with `tnl publisher revoke <publisher-identity-id> --team studio`.
Deleting the stack leaves EFS, access points, mount targets, their security groups,
and managed log groups behind. Remove those after retiring the identities and
saving any data you need.

## regenerate or check

For a different output directory, use the same path for generation and checks,
and pass it to bootstrap as `--generated-dir`:

```sh
tnl generate --output-dir infrastructure/generated
tnl generate --check --output-dir infrastructure/generated
```

The `fargate.*` files beside this guide are generated examples. Use `tnl generate`
for your own project. Contributors can refresh and check the examples from the
tnl repository root:

```sh
mise exec -- task generate
mise exec -- task deploy:publishers:check
```
