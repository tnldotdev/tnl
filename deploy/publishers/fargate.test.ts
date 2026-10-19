import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { z } from "zod";

const record = z.record(z.string(), z.unknown());
const template = z
  .object({
    Parameters: z.record(z.string(), record),
    Resources: z.record(
      z.string(),
      z.object({
        Type: z.string(),
        Properties: record,
        DeletionPolicy: z.string().optional(),
        UpdateReplacePolicy: z.string().optional(),
      }),
    ),
    Outputs: record,
  })
  .parse(parse(readFileSync(new URL("fargate.yaml", import.meta.url), "utf8")));

function properties(name: string, type: string): Record<string, unknown> {
  const resource = template.Resources[name];
  expect(resource?.Type).toBe(type);
  return record.parse(resource?.Properties);
}

describe("generated Fargate group boundary", () => {
  it("requires a digest and rejects tags and credentials", () => {
    const image = new RegExp(
      `^(?:${z.string().parse(template.Parameters.PublisherImage?.AllowedPattern)})$`,
    );
    const digest = "a".repeat(64);
    for (const valid of [
      `ghcr.io/tnldotdev/tnl@sha256:${digest}`,
      `registry.example.com:5000/team/publisher@sha256:${digest}`,
    ])
      expect(image.test(valid)).toBe(true);
    for (const invalid of [
      "ghcr.io/tnldotdev/tnl:latest",
      `ghcr.io/tnldotdev/tnl:v1@sha256:${digest}`,
      `https://ghcr.io/tnldotdev/tnl@sha256:${digest}`,
      `user:password@ghcr.io/tnldotdev/tnl@sha256:${digest}`,
      `ghcr.io/tnldotdev/tnl@sha256:${"a".repeat(63)}`,
    ])
      expect(image.test(invalid)).toBe(false);
  });

  for (const index of [1, 2]) {
    const prefix = `Replica${index}`;
    it(`runs independent replica ${index} without surge or enrollment`, () => {
      const task = properties(`${prefix}TaskDefinition`, "AWS::ECS::TaskDefinition");
      const [container] = z.array(record).length(1).parse(task.ContainerDefinitions);
      expect(container).toMatchObject({
        User: "65532:65532",
        EntryPoint: ["/usr/local/bin/tnl"],
        Command: [
          "--no-config",
          "publisher",
          "serve",
          "--server",
          { Ref: "ControlURL" },
          "--project-key",
          { Ref: "ProjectKey" },
          "--group",
          { Ref: "Group" },
          "--state-dir",
          "/state",
          "--instance",
          { Ref: `${prefix}Instance` },
          "--identity-dir",
          "/identity",
        ],
        LinuxParameters: { Capabilities: { Drop: ["ALL"] } },
        StopTimeout: 120,
        MountPoints: [{ SourceVolume: "identity", ContainerPath: "/identity", ReadOnly: false }],
        Secrets: [
          {
            Name: "TNL_GROUP_IDENTITY",
            ValueFrom: {
              "Fn::Sub": `\${${prefix}IdentitySecretArn}:::\${${prefix}IdentitySecretVersion}`,
            },
          },
        ],
      });
      expect(container).not.toHaveProperty("Environment");
      expect(container).not.toHaveProperty("PortMappings");
      expect(container).not.toHaveProperty("Privileged", true);
      expect(task.Volumes).toMatchObject([
        {
          Name: "identity",
          EFSVolumeConfiguration: {
            TransitEncryption: "ENABLED",
            AuthorizationConfig: {
              AccessPointId: { Ref: `${prefix}IdentityAccessPoint` },
              IAM: "ENABLED",
            },
          },
        },
      ]);
      expect(template.Parameters[`${prefix}IdentitySecretVersion`]).not.toHaveProperty("Default");
      expect(template.Parameters[`${prefix}DesiredCount`]).toMatchObject({
        Default: "1",
        AllowedValues: ["0", "1"],
      });
      expect(properties(`${prefix}Service`, "AWS::ECS::Service")).toMatchObject({
        DesiredCount: { Ref: `${prefix}DesiredCount` },
        EnableExecuteCommand: false,
        AvailabilityZoneRebalancing: "DISABLED",
        DeploymentConfiguration: {
          MinimumHealthyPercent: 0,
          MaximumPercent: 100,
          DeploymentCircuitBreaker: { Enable: true, Rollback: false },
        },
      });
      expect(properties(`${prefix}IdentityAccessPoint`, "AWS::EFS::AccessPoint")).toMatchObject({
        PosixUser: { Uid: "65532", Gid: "65532" },
        RootDirectory: {
          Path: { "Fn::Sub": `/tnl/\${DeploymentID}/replica-${index}` },
          CreationInfo: { OwnerUid: "65532", OwnerGid: "65532", Permissions: "0700" },
        },
      });
      expect(template.Resources[`${prefix}IdentityAccessPoint`]).toMatchObject({
        DeletionPolicy: "Retain",
        UpdateReplacePolicy: "Retain",
      });
      const role = JSON.stringify(properties(`${prefix}TaskRole`, "AWS::IAM::Role"));
      expect(role).toContain("elasticfilesystem:AccessPointArn");
      expect(role).toContain("aws:SecureTransport");
      expect(role).not.toMatch(/secretsmanager|ClientRootAccess|"Resource":"\*"/);
      const execution = JSON.stringify(properties(`${prefix}ExecutionRole`, "AWS::IAM::Role"));
      expect(execution).toContain("secretsmanager:VersionId");
      expect(execution).toContain("kms:EncryptionContext:SecretARN");
      expect(execution).toContain("kms:ViaService");
      expect(execution).not.toContain('"Resource":"*"');
    });
  }

  it("keeps runtime SQLite task-local and enforces the image filesystem contract", () => {
    const dockerfile = readFileSync(new URL("../../Dockerfile", import.meta.url), "utf8");
    expect(dockerfile).toContain("install -d -m 0700 /out/client-state");
    expect(dockerfile).toContain(
      "COPY --from=build --chown=65532:65532 --chmod=0700 /out/client-state /state",
    );
    expect(dockerfile).toContain("USER 65532:65532");
    expect(dockerfile).toContain("ENV TNL_STATE_DIR=/state");
    expect(JSON.stringify(template.Resources)).not.toMatch(
      /TNL_GROUP_ENROLL_KEY|PutSecretValue|AWS::SecretsManager::Secret|AWS::Lambda::|AWS::EC2::VPC"/,
    );
    expect(properties("PublisherSecurityGroup", "AWS::EC2::SecurityGroup")).not.toHaveProperty(
      "SecurityGroupIngress",
    );
    expect(properties("EFSSecurityGroup", "AWS::EC2::SecurityGroup")).toMatchObject({
      SecurityGroupIngress: [{ IpProtocol: "tcp", FromPort: 2049, ToPort: 2049 }],
    });
    expect(template.Resources.IdentityFileSystem).toMatchObject({
      DeletionPolicy: "Retain",
      UpdateReplacePolicy: "Retain",
      Properties: { Encrypted: true },
    });
    expect(template.Resources.IdentityFileSystem).not.toHaveProperty("Condition");
    expect(template.Parameters).not.toHaveProperty("ExistingFileSystemId");
    expect(properties("IdentityFileSystem", "AWS::EFS::FileSystem")).not.toHaveProperty(
      "AvailabilityZoneName",
    );
    for (const name of [
      "PublisherSecurityGroup",
      "EFSSecurityGroup",
      ...Array.from({ length: 6 }, (_, i) => `MountTarget${i + 1}`),
    ]) {
      expect(template.Resources[name]).toMatchObject({
        DeletionPolicy: "Retain",
        UpdateReplacePolicy: "Retain",
      });
    }
  });
});
