import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { TestContainerRunner } from "./test-container-runner.ts";

const separator = process.argv.indexOf("--", 2);
if (separator === -1 || separator === process.argv.length - 1) {
  throw new Error("usage: node scripts/run-go-tests-with-postgres.ts -- COMMAND [ARGUMENTS...]");
}

const root = path.resolve(import.meta.dirname, "..");
const tlsEnabled = process.argv.slice(2, separator).includes("--tls");
const sharedCertificate = process.argv.slice(2, separator).includes("--shared-cert");
if (sharedCertificate && !tlsEnabled) throw new Error("--shared-cert requires --tls");
const identity = createHash("sha256").update(root).digest("hex").slice(0, 12);
// distinct invocations from one checkout must not remove each other's database.
const container = `tnl-test-postgres-${identity}-${randomUUID()}`;
const image =
  "public.ecr.aws/docker/library/postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94";
const command = process.argv[separator + 1];
if (command === undefined) throw new Error("test command is required");
const arguments_ = process.argv.slice(separator + 2);
const runner = new TestContainerRunner(container);
const certificateDirectory = tlsEnabled
  ? await mkdtemp(path.join(os.tmpdir(), "tnl-test-postgres-tls-"))
  : undefined;

try {
  await runner.remove();
  await runner.run("docker", [
    "run",
    "--detach",
    "--rm",
    "--name",
    container,
    "--publish",
    "127.0.0.1::5432",
    "--env",
    "POSTGRES_DB=postgres",
    "--env",
    "POSTGRES_PASSWORD=postgres",
    "--env",
    "POSTGRES_USER=postgres",
    "--health-cmd",
    "pg_isready --username postgres --dbname postgres",
    "--health-interval",
    "1s",
    "--health-timeout",
    "5s",
    "--health-retries",
    "30",
    image,
  ]);
  await waitForHealthy();
  if (certificateDirectory !== undefined) {
    const certificate = path.join(certificateDirectory, "server.crt");
    const key = path.join(certificateDirectory, "server.key");
    await runner.run("openssl", [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      key,
      "-out",
      certificate,
      "-days",
      "1",
      "-subj",
      "/CN=route.example",
      "-addext",
      "subjectAltName=DNS:route.example,DNS:db.internal",
    ]);
    await runner.run("docker", [
      "cp",
      certificate,
      `${container}:/var/lib/postgresql/data/server.crt`,
    ]);
    await runner.run("docker", ["cp", key, `${container}:/var/lib/postgresql/data/server.key`]);
    await runner.run("docker", [
      "exec",
      "--user",
      "root",
      container,
      "chown",
      "postgres:postgres",
      "/var/lib/postgresql/data/server.crt",
      "/var/lib/postgresql/data/server.key",
    ]);
    await runner.run("docker", [
      "exec",
      "--user",
      "root",
      container,
      "chmod",
      "0600",
      "/var/lib/postgresql/data/server.key",
    ]);
    await runner.run("docker", [
      "exec",
      container,
      "psql",
      "--username",
      "postgres",
      "--dbname",
      "postgres",
      "-c",
      "ALTER SYSTEM SET ssl = on",
    ]);
    await runner.run("docker", [
      "exec",
      "--user",
      "postgres",
      container,
      "pg_ctl",
      "-D",
      "/var/lib/postgresql/data",
      "reload",
    ]);
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const enabled = (
        await runner.output("docker", [
          "exec",
          container,
          "psql",
          "--username",
          "postgres",
          "--dbname",
          "postgres",
          "-tAc",
          "SHOW ssl",
        ])
      ).trim();
      if (enabled === "on") break;
      if (attempt === 29) throw new Error("disposable PostgreSQL TLS did not become ready");
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
  const port = await runner.port(5432);
  const postgresURL = `postgres://postgres:postgres@127.0.0.1:${port}/postgres?sslmode=disable`;
  const result = await runner.run(
    command,
    [
      ...arguments_,
      `-tnl-test-postgres-url=${postgresURL}`,
      ...(certificateDirectory === undefined
        ? []
        : [
            `-tnl-test-postgres-ca=${path.join(certificateDirectory, "server.crt")}`,
            ...(sharedCertificate
              ? [`-tnl-test-postgres-key=${path.join(certificateDirectory, "server.key")}`]
              : []),
          ]),
    ],
    true,
  );
  process.exitCode = result;
} catch (error) {
  try {
    const logs = await runner.output("docker", ["logs", container]);
    if (logs !== "") process.stderr.write(logs);
  } catch {
    // the container may have failed before it was created.
  }
  throw error;
} finally {
  await runner.remove();
  if (certificateDirectory !== undefined)
    await rm(certificateDirectory, { recursive: true, force: true });
}

async function waitForHealthy() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const status = await runner.output("docker", [
      "inspect",
      "--format",
      "{{.State.Health.Status}}",
      container,
    ]);
    if (status.trim() === "healthy") return;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("PostgreSQL test container did not become healthy");
}
