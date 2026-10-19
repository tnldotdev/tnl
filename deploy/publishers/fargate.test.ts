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

describe("Fargate publisher infrastructure boundary", () => {
  it("requires a digest and rejects tagged, credentialed, or malformed images", () => {
    const pattern = z.string().parse(template.Parameters.PublisherImage?.AllowedPattern);
    const image = new RegExp(`^(?:${pattern})$`);
    const digest = "a".repeat(64);
    for (const valid of [
      `ghcr.io/tnldotdev/tnl@sha256:${digest}`,
      `registry.example.com:5000/team/publisher@sha256:${digest}`,
    ]) {
      expect(image.test(valid), valid).toBe(true);
    }
    for (const invalid of [
      "ghcr.io/tnldotdev/tnl:latest",
      "ghcr.io/tnldotdev/tnl:v1.0.0",
      `ghcr.io/tnldotdev/tnl:v1@sha256:${digest}`,
      `https://ghcr.io/tnldotdev/tnl@sha256:${digest}`,
      `user:password@ghcr.io/tnldotdev/tnl@sha256:${digest}`,
      `ghcr.io/tnldotdev/tnl@sha256:${"a".repeat(63)}`,
    ]) {
      expect(image.test(invalid), invalid).toBe(false);
    }
  });

  it("runs the group command with durable identity files and disposable local SQLite", () => {
    const task = properties("TaskDefinition", "AWS::ECS::TaskDefinition");
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
        { Ref: "Instance" },
        "--identity-dir",
        "/identity",
      ],
      LinuxParameters: { Capabilities: { Drop: ["ALL"] } },
    });
    expect(container).not.toHaveProperty("Privileged", true);
    expect(container).not.toHaveProperty("PortMappings");
    expect(container?.MountPoints).toEqual([
      { SourceVolume: "identity", ContainerPath: "/identity", ReadOnly: false },
    ]);
    expect(task.Volumes).toEqual([
      {
        Name: "identity",
        EFSVolumeConfiguration: {
          FilesystemId: { Ref: "IdentityFileSystemId" },
          TransitEncryption: "ENABLED",
          AuthorizationConfig: { AccessPointId: { Ref: "IdentityAccessPoint" }, IAM: "ENABLED" },
        },
      },
    ]);
    const dockerfile = readFileSync(new URL("../../Dockerfile", import.meta.url), "utf8");
    expect(dockerfile).toContain("install -d -m 0700 /out/client-state");
    expect(dockerfile).toContain(
      "COPY --from=build --chown=65532:65532 --chmod=0700 /out/client-state /state",
    );
    expect(dockerfile).toContain("USER 65532:65532");
    expect(dockerfile).toContain("ENV TNL_STATE_DIR=/state");
  });

  it("reuses a version-pinned durable identity on every replacement without enrollment", () => {
    const task = properties("TaskDefinition", "AWS::ECS::TaskDefinition");
    const [container] = z.array(record).length(1).parse(task.ContainerDefinitions);
    expect(container?.Secrets).toEqual([
      {
        Name: "TNL_GROUP_IDENTITY",
        ValueFrom: { "Fn::Sub": "${IdentitySecretArn}:::${IdentitySecretVersion}" },
      },
    ]);
    const version = template.Parameters.IdentitySecretVersion;
    expect(version).not.toHaveProperty("Default");
    const pattern = new RegExp(`^(?:${z.string().parse(version?.AllowedPattern)})$`);
    expect(pattern.test("")).toBe(false);
    expect(pattern.test("12345678-1234-1234-1234-123456789012")).toBe(true);
    expect(JSON.stringify(template.Resources)).not.toMatch(/TNL_GROUP_ENROLL_KEY|PutSecretValue/);
    expect(container).not.toHaveProperty("Environment");
    const publicValues = JSON.stringify([container?.Command, template.Outputs]);
    expect(publicValues).not.toMatch(/enroll|secret|access.token|login|password/i);
  });

  it("separates identity injection from replica-private certificate storage", () => {
    const task = properties("TaskDefinition", "AWS::ECS::TaskDefinition");
    expect(task.ExecutionRoleArn).toEqual({ "Fn::GetAtt": ["ExecutionRole", "Arn"] });
    expect(task.TaskRoleArn).toEqual({ "Fn::GetAtt": ["TaskRole", "Arn"] });
    const execution = properties("ExecutionRole", "AWS::IAM::Role");
    const [policy] = z
      .array(z.object({ PolicyDocument: record }))
      .length(1)
      .parse(execution.Policies);
    const statements = z.array(record).parse(policy?.PolicyDocument.Statement);
    expect(statements).toContainEqual({
      Effect: "Allow",
      Action: "secretsmanager:GetSecretValue",
      Resource: { Ref: "IdentitySecretArn" },
      Condition: {
        StringEquals: { "secretsmanager:VersionId": { Ref: "IdentitySecretVersion" } },
      },
    });
    expect(statements).toContainEqual({
      "Fn::If": [
        "HasIdentityKMSKey",
        {
          Effect: "Allow",
          Action: "kms:Decrypt",
          Resource: { Ref: "IdentityKMSKeyArn" },
          Condition: {
            StringEquals: {
              "kms:ViaService": {
                "Fn::Sub": "secretsmanager.${AWS::Region}.${AWS::URLSuffix}",
              },
              "kms:EncryptionContext:SecretARN": { Ref: "IdentitySecretArn" },
            },
          },
        },
        { Ref: "AWS::NoValue" },
      ],
    });
    const role = properties("TaskRole", "AWS::IAM::Role");
    const [taskPolicy] = z
      .array(z.object({ PolicyDocument: record }))
      .length(1)
      .parse(role.Policies);
    const taskStatements = z.array(record).length(1).parse(taskPolicy?.PolicyDocument.Statement);
    expect(taskStatements).toContainEqual({
      Effect: "Allow",
      Action: ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"],
      Resource: {
        "Fn::Sub":
          "arn:${AWS::Partition}:elasticfilesystem:${AWS::Region}:${AWS::AccountId}:file-system/${IdentityFileSystemId}",
      },
      Condition: {
        StringEquals: {
          "elasticfilesystem:AccessPointArn": { "Fn::GetAtt": ["IdentityAccessPoint", "Arn"] },
        },
        Bool: { "aws:SecureTransport": "true" },
      },
    });
    expect(role).not.toHaveProperty("ManagedPolicyArns");
    expect(JSON.stringify(role)).not.toMatch(/secretsmanager|DeleteObject|"Resource":"\*"/);
    expect(JSON.stringify(execution)).not.toMatch(/"Resource":"\*"/);
  });

  it("retains a replica-private access point with owner-only permissions", () => {
    expect(properties("IdentityAccessPoint", "AWS::EFS::AccessPoint")).toEqual({
      FileSystemId: { Ref: "IdentityFileSystemId" },
      PosixUser: { Uid: "65532", Gid: "65532" },
      RootDirectory: {
        Path: { "Fn::Sub": "/tnl/${AWS::StackName}" },
        CreationInfo: { OwnerUid: "65532", OwnerGid: "65532", Permissions: "0700" },
      },
    });
    expect(template.Resources.IdentityAccessPoint).toMatchObject({
      DeletionPolicy: "Retain",
      UpdateReplacePolicy: "Retain",
    });
    expect(Object.values(template.Resources).some(({ Type }) => Type.startsWith("AWS::S3::"))).toBe(
      false,
    );
  });

  it("keeps capacity, replacement, and outbound networking in infrastructure", () => {
    expect(template.Parameters.DesiredCount).toMatchObject({ Default: 1, AllowedValues: [0, 1] });
    const service = properties("Service", "AWS::ECS::Service");
    expect(service).toMatchObject({
      DesiredCount: { Ref: "DesiredCount" },
      EnableExecuteCommand: false,
      AvailabilityZoneRebalancing: "DISABLED",
      DeploymentConfiguration: {
        MinimumHealthyPercent: 0,
        MaximumPercent: 100,
        DeploymentCircuitBreaker: { Enable: true, Rollback: false },
      },
      NetworkConfiguration: {
        AwsvpcConfiguration: {
          AssignPublicIp: "DISABLED",
          Subnets: { Ref: "Subnets" },
          SecurityGroups: { Ref: "SecurityGroupIds" },
        },
      },
    });
    expect(service).not.toHaveProperty("LoadBalancers");
    expect(
      Object.values(template.Resources).some(({ Type }) => Type.includes("SecurityGroup")),
    ).toBe(false);
    const group = new RegExp(
      `^(?:${z.string().parse(template.Parameters.Group?.AllowedPattern)})$`,
    );
    expect(group.test("production")).toBe(true);
    expect(group.test("local")).toBe(false);
  });
});
