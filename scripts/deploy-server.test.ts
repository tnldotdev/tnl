import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";
import { hasStagingIngressPorts } from "./deploy-server.ts";

test("staging port checks require all four PROXY v2 destinations and ingress-a", () => {
  const port = (value: Record<string, number>) => ({
    ...value,
    handlers: ["proxy_proto"],
    proxy_proto_options: { version: "v2" },
  });
  const member: Parameters<typeof hasStagingIngressPorts>[0] = {
    id: "ingress-1",
    state: "started",
    image_ref: { digest: "sha256:test" },
    config: {
      env: { TNLD_INGRESS_POOL_ID: "ingress-a" },
      services: [
        {
          protocol: "tcp",
          internal_port: 8443,
          ports: [
            port({ port: 443 }),
            port({ port: 3306 }),
            port({ port: 5432 }),
            port({ start_port: 10000, end_port: 10031 }),
          ],
        },
      ],
    },
  };
  expect(hasStagingIngressPorts(member)).toBe(true);
  const ports = member.config.services[0]?.ports;
  const options = ports?.[3]?.proxy_proto_options;
  if (!ports || !options) throw new Error("missing port fixture");
  options.version = "v1";
  expect(hasStagingIngressPorts(member)).toBe(false);
  options.version = "v2";
  member.config.env.TNLD_INGRESS_POOL_ID = "ingress-b";
  expect(hasStagingIngressPorts(member)).toBe(false);
  member.config.env.TNLD_INGRESS_POOL_ID = "ingress-a";
  ports.pop();
  expect(hasStagingIngressPorts(member)).toBe(false);
});

test("deployment rejects an unpinned image without exposing the database URL", () => {
  const result = spawnSync(
    process.execPath,
    [
      fileURLToPath(new URL("./deploy-server.ts", import.meta.url)),
      "production",
      "ghcr.io/tnldotdev/tnl:latest",
      "0.1.0-rc.41",
      "a".repeat(40),
    ],
    {
      encoding: "utf8",
      env: { ...process.env, TNLD_DATABASE_DIRECT_URL: "private-test-secret" },
    },
  );
  expect(result.status).toBe(1);
  expect(result.stderr).toBe("server deployment: invalid image digest\n");
  expect(result.stdout).toBe("");
});

test("staging rejects a production Environment branch before starting Fly", () => {
  const commit = "a".repeat(40);
  const result = spawnSync(
    process.execPath,
    [
      fileURLToPath(new URL("./deploy-server.ts", import.meta.url)),
      "staging",
      `ghcr.io/tnldotdev/tnl@sha256:${"b".repeat(64)}`,
      `main-${commit}`,
      commit,
    ],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        TNLD_DATABASE_BRANCH: "production",
        TNLD_DATABASE_DIRECT_URL: "postgres://migrator:private-test-secret@db.pg.psdb.cloud/tnl",
      },
    },
  );
  expect(result.status).toBe(1);
  expect(result.stderr).toBe("server deployment: database branch does not match staging\n");
  expect(result.stdout).toBe("");
});
