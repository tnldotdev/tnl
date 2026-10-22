# publisher generation and bootstrap boundary

`internal/publisher/deployment` owns schema version 1, the fixed AWS stack renderer,
artifact ownership and nonsecret parameter serialization. Bootstrap consumers
import:

```go
import "github.com/tnldotdev/tnl/internal/publisher/deployment"
```

The offline command loads project config without client state and calls:

```go
source, err := project.SourceIdentity(ctx)
bundle, err := publisherdeployment.Generate(project.Config, source)
err = bundle.Write(outputDir) // explicit generation
err = bundle.Check(outputDir) // read-only exact-byte check
```

`SourceIdentity.Key` and `.Fingerprint` are the existing Git-source identity,
not HEAD, a path, or an installation identifier. The manifest has no timestamps,
absolute paths, sessions, target data or secret values. Only AWS-declared groups
appear, ordered by configuration selector. `configuration_fingerprint` hashes
the normalized `{name, replicas}` deployment intent, including the default of
one replica. Services and group policy are reconciled separately by apply.

## exported contract

```go
type Manifest struct {
    SchemaVersion     int         `json:"schema_version"`
    ProjectKey        string      `json:"project_key"`
    SourceFingerprint string      `json:"source_fingerprint"`
    DocumentationPath string      `json:"documentation_path"`
    DocumentationSHA256 string    `json:"documentation_sha256"`
    Publishers        []Publisher `json:"publishers"`
}

type Publisher struct {
    Name                     string    `json:"name"`
    Provider                 string    `json:"provider"`
    ConfigurationFingerprint string    `json:"configuration_fingerprint"`
    TemplatePath             string    `json:"template_path"`
    TemplateSHA256           string    `json:"template_sha256"`
    ParametersExamplePath    string    `json:"parameters_example_path"`
    ParametersExampleSHA256  string    `json:"parameters_example_sha256"`
    Replicas                 []Replica `json:"replicas"`
}

type Replica struct {
    Key                            string `json:"key"`
    IdentitySecretARNParameter     string `json:"identity_secret_arn_parameter"`
    IdentitySecretVersionParameter string `json:"identity_secret_version_parameter"`
    InstanceParameter              string `json:"instance_parameter"`
    PublisherIdentityIDParameter   string `json:"publisher_identity_id_parameter"`
}

type Parameters map[string]string
type Parameter struct {
    ParameterKey   string `json:"ParameterKey"`
    ParameterValue string `json:"ParameterValue"`
}
```

`Provider` is exactly `aws`. Paths are relative to the selected output root:
`aws/NAME.yaml`, `aws/NAME.storage-policy.json` and `aws/NAME.parameters.example.json`. the manifest requires the storage-policy path and hash alongside the template and parameter example. manifest schema 1 and template version 2 are fixed. Replica keys are fixed
`replica-1` through `replica-N`; parameter names for replica 1 are exactly:

```text
Replica1IdentitySecretArn
Replica1IdentitySecretVersion
Replica1Instance
Replica1PublisherIdentityID
```

These are validated, not arbitrary manifest-controlled parameter names or paths.
`config.MaxPublisherReplicas` is 8. The package also exports `SchemaVersion`,
`TemplateVersion`, `DefaultOutputDir`, `ManifestPath`, `DocumentationPath`, `MaxManifestBytes` (256 KiB)
and `MaxArtifactBytes` (1 MiB).

## validate before identity operations

Bootstrap must evaluate current config and source identity, then validate before
contacting control or AWS:

```go
manifest, err := publisherdeployment.Validate(outputDir, project.Config, source)
if err != nil { return err }
publisher, err := manifest.FindPublisher(groupSelector)
if err != nil { return err }
```

`Validate` calls bounded `Read(outputDir)`, validates exact paths/schema/replica
contracts, verifies the generated readme and both artifact hashes for every publisher, and
compares with a fresh render of the current deployment configuration and source.
`Manifest.Validate()` performs the structural checks alone. `Read` rejects
unknown/duplicate JSON fields, oversized/nonregular files and symlink paths.
`FindPublisher` also validates the manifest. Hashes detect stale or edited bytes;
they are not signatures or a substitute for reviewing trusted config and tools.

`Bundle.Check` compares exact manifest and artifact bytes and performs no writes.
`Bundle.Write` validates ownership, preflights conflicts, writes artifacts by
exclusive temporary file and rename, removes unchanged retired artifacts and
writes the manifest last. An interrupted write is detectable and repairable by
generation; this is not an atomic multi-file transaction. It never scans or
deletes unrelated custom files. Output must not contain symlink components.

## bootstrap parameter map

Bootstrap owns actual control IDs, DeploymentID, secret containers, secret JSON,
and pinned versions. Populate a `publisherdeployment.Parameters` map:

```go
values := publisherdeployment.Parameters{
    publisherdeployment.ControlURLParameter:       controlURL,
    publisherdeployment.ProjectKeyParameter:       manifest.ProjectKey,
    publisherdeployment.GroupParameter:            publisher.Name,
    publisherdeployment.TeamIDParameter:           teamID,
    publisherdeployment.PublisherGroupIDParameter: groupID,
    publisherdeployment.DeploymentIDParameter:     deploymentID,
    publisherdeployment.TemplateSHA256Parameter:   publisher.TemplateSHA256,
}
for _, replica := range publisher.Replicas {
    // use the independently provisioned result for this stable replica key.
    values[replica.InstanceParameter] = provisioned[replica.Key].Instance
    values[replica.PublisherIdentityIDParameter] = provisioned[replica.Key].PublisherID
    values[replica.IdentitySecretARNParameter] = provisioned[replica.Key].SecretARN
    values[replica.IdentitySecretVersionParameter] = provisioned[replica.Key].VersionID
}
parameters := values.CloudFormation() // sorted []Parameter for AWS parameter JSON
```

The constants' values are their names without the `Parameter` suffix. All values
in this map are public IDs or references; never put private JSON, signing keys,
person sessions or enrollment keys here. Bootstrap must preserve DeploymentID
and surviving per-replica identities across updates and validate the returned
identity JSON against actual scope. It does not change generated examples.
Customer infrastructure settings are merged by deployment tooling from a
separate parameter file. See [deployment parameters](../../../deploy/publisher/fargate/readme.md#deployment-parameters).

`AWSParameter` is the renderer's authoritative definition for each CloudFormation
input (`Type`, `Description`, `Default`, `AllowedPattern`, `AllowedValues`,
`MaxLength`). It drives both template parameters and generated examples.
`RenderAWS(Publisher, projectKey)` produces template and example bytes for a
validated fixed replica contract. There is no general IaC compiler or
infrastructure apply API in this package.

Template version 2 injects the nonsecret deployment ID, provider, manifest replica
key, image reference and template version/hash into each publisher process. The
publisher reports these through its existing signed runtime owner; see
[deployment provenance](publisher-provenance.md) for exact environment and API
fields and the limits of this publisher-reported evidence.
