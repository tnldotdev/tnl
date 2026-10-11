import { randomUUID } from "node:crypto";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { TestContainerRunner } from "./test-container-runner.ts";

const separator = process.argv.indexOf("--", 2);
if (separator < 0 || separator === process.argv.length - 1) {
  throw new Error("usage: node scripts/run-go-tests-with-mysql.ts -- COMMAND [ARGUMENTS...]");
}
const command = process.argv[separator + 1];
if (command === undefined) throw new Error("test command is required");

const image =
  "public.ecr.aws/docker/library/mysql:8.4@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242";
const container = `tnl-test-mysql-${randomUUID()}`;
const directory = await mkdtemp(path.join(os.tmpdir(), "tnl-test-mysql-certs-"));
const certificate = path.join(directory, "server.pem");
const privateKey = path.join(directory, "server.key");
const runner = new TestContainerRunner(container);

try {
  await chmod(directory, 0o755);
  await runner.run("openssl", [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    privateKey,
    "-out",
    certificate,
    "-days",
    "1",
    "-subj",
    "/CN=db.internal",
    "-addext",
    "subjectAltName=DNS:db.internal",
  ]);
  await chmod(privateKey, 0o644); // disposable test certificate read by the mysql container user.
  await runner.run("docker", [
    "run",
    "--detach",
    "--rm",
    "--name",
    container,
    "--publish",
    "127.0.0.1::3306",
    "--volume",
    `${directory}:/tnl-test-certs:ro`,
    "--env",
    "MYSQL_ROOT_PASSWORD=testpass",
    "--env",
    "MYSQL_ROOT_HOST=%",
    "--health-cmd",
    "mysqladmin ping --silent --host=127.0.0.1 --user=root --password=testpass",
    "--health-interval",
    "1s",
    "--health-timeout",
    "5s",
    "--health-retries",
    "60",
    image,
    "--ssl-cert=/tnl-test-certs/server.pem",
    "--ssl-key=/tnl-test-certs/server.key",
    "--require_secure_transport=ON",
  ]);
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const health = (
      await runner.output("docker", ["inspect", "--format", "{{.State.Health.Status}}", container])
    ).trim();
    if (health === "healthy") break;
    if (health === "unhealthy" || attempt === 119)
      throw new Error("MySQL test container did not become healthy");
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  const port = await runner.port(3306);
  process.exitCode = await runner.run(
    command,
    [
      ...process.argv.slice(separator + 2),
      `-tnl-test-mysql-address=127.0.0.1:${port}`,
      `-tnl-test-mysql-ca=${certificate}`,
    ],
    true,
    true,
  );
} catch (error) {
  try {
    const logs = await runner.output("docker", ["logs", container]);
    if (logs !== "") process.stderr.write(logs);
  } catch {
    // startup may have failed before the container was created.
  }
  throw error;
} finally {
  await runner.remove();
  await rm(directory, { recursive: true, force: true });
}
