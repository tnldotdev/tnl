import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";

const separator = process.argv.indexOf("--", 2);
if (separator < 0 || separator === process.argv.length - 1) {
  throw new Error("usage: node scripts/run-go-tests-with-mysql.ts -- COMMAND [ARGUMENTS...]");
}
const command = process.argv[separator + 1];
if (command === undefined) throw new Error("test command is required");

const image =
  "docker.io/library/mysql:8.4@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242";
const container = `tnl-test-mysql-${randomUUID()}`;
const directory = await mkdtemp(path.join(os.tmpdir(), "tnl-test-mysql-certs-"));
const certificate = path.join(directory, "server.pem");
const privateKey = path.join(directory, "server.key");
let testProcess: ChildProcess | undefined;
let stopping = false;

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, async () => {
    if (stopping) return;
    stopping = true;
    testProcess?.kill(signal);
    await removeContainer();
    process.exitCode = 1;
  });
}

try {
  await chmod(directory, 0o755);
  await run("openssl", [
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
  await run("docker", [
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
      await output("docker", ["inspect", "--format", "{{.State.Health.Status}}", container])
    ).trim();
    if (health === "healthy") break;
    if (health === "unhealthy" || attempt === 119)
      throw new Error("MySQL test container did not become healthy");
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  const mapping = (await output("docker", ["port", container, "3306/tcp"])).trim();
  const port = mapping.match(/:([0-9]+)$/)?.[1];
  if (port === undefined) throw new Error(`unexpected MySQL port mapping ${mapping}`);
  process.exitCode = await run(
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
    const logs = await output("docker", ["logs", container]);
    if (logs !== "") process.stderr.write(logs);
  } catch {
    // startup may have failed before the container was created.
  }
  throw error;
} finally {
  await removeContainer();
  await rm(directory, { recursive: true, force: true });
}

async function removeContainer() {
  await run("docker", ["rm", "--force", container], false, true);
}

function output(executable: string, arguments_: readonly string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, arguments_, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (data: string) => (stdout += data));
    child.stderr.setEncoding("utf8").on("data", (data: string) => (stderr += data));
    child.once("error", reject);
    child.once("close", (code) => {
      if (code === 0) resolve(stdout);
      else reject(new Error(`${executable} exited with ${code}: ${stderr.trim()}`));
    });
  });
}

function run(
  executable: string,
  arguments_: readonly string[],
  inherited = false,
  allowFailure = false,
): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, arguments_, {
      stdio: inherited ? "inherit" : ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr?.setEncoding("utf8").on("data", (data: string) => {
      stderr = (stderr + data).slice(-4096);
    });
    if (inherited) testProcess = child;
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (inherited) testProcess = undefined;
      if (code === 0 || allowFailure) resolve(code ?? 1);
      else reject(new Error(`${executable} exited with ${signal ?? code}: ${stderr.trim()}`));
    });
  });
}
