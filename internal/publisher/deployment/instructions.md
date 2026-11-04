# generated publisher deployment

Commit this directory with your project configuration. `manifest.json` lists the
generated AWS files for each publisher group:

- `aws/NAME.yaml`: the CloudFormation stack;
- `aws/NAME.storage-policy.json`: the policy that protects persistent identity storage;
- `aws/NAME.parameters.example.json`: deployment settings to copy and fill in.

For a group named `production`, run this from the project root:

```sh
cp .tnl/generated/aws/production.parameters.example.json production.parameters.json
```

Prepare the replica identities with `tnl apply` and `tnl bootstrap production`,
then fill the copy with the returned parameter bindings and your AWS settings.
Replace every `REQUIRED` value. Keep signing keys in Secrets Manager; parameter
files hold only references.

Next, deploy the YAML with your CloudFormation workflow, supplying the completed
parameters and the generated storage policy. Keep each replica's identity secret
and EFS storage across updates. Follow the
[deployment guide](https://github.com/tnldotdev/tnl/blob/main/deploy/publisher/fargate/readme.md)
for bootstrap, networking, and deployment commands.

Regenerate after changing project configuration, and check before deploying:

```sh
tnl generate
tnl generate --check
```

If you chose a custom directory, adjust the copy path above and use the same
directory for generation and checks:

```sh
tnl generate --output-dir infrastructure/generated
tnl generate --check --output-dir infrastructure/generated
```

Pass that directory to bootstrap with `--generated-dir` too. Edit your copied
parameter file, not the generated examples. Generation updates files only;
bootstrap prepares identities; your CloudFormation workflow deploys the stack.
