import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import path from "node:path";
import process from "node:process";

const separator = process.argv.indexOf("--", 2);
if (separator === -1 || separator === process.argv.length - 1) {
  throw new Error("usage: node scripts/run-go-tests-with-postgres.mjs -- COMMAND [ARGUMENTS...]");
}

const root = path.resolve(import.meta.dirname, "..");
const identity = createHash("sha256").update(root).digest("hex").slice(0, 12);
const container = `tnl-test-postgres-${identity}`;
const image =
  "postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94";
const command = process.argv[separator + 1];
const arguments_ = process.argv.slice(separator + 2);
let testProcess;
let stopping = false;

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, async () => {
    if (stopping) return;
    stopping = true;
    testProcess?.kill(signal);
    await removeContainer();
    process.exitCode = 1;
  });
}

try {
  await removeContainer();
  await run("docker", [
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
  const mapping = (await output("docker", ["port", container, "5432/tcp"])).trim();
  const port = mapping.match(/:([0-9]+)$/)?.[1];
  if (port === undefined) throw new Error(`unexpected PostgreSQL port mapping ${mapping}`);
  const postgresURL = `postgres://postgres:postgres@127.0.0.1:${port}/postgres?sslmode=disable`;
  const result = await run(command, [...arguments_, `-tnl-test-postgres-url=${postgresURL}`], true);
  process.exitCode = result;
} catch (error) {
  try {
    const logs = await output("docker", ["logs", container]);
    if (logs !== "") process.stderr.write(logs);
  } catch {
    // The container may have failed before it was created.
  }
  throw error;
} finally {
  await removeContainer();
}

async function waitForHealthy() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const status = await output("docker", [
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

async function removeContainer() {
  await run("docker", ["rm", "--force", container], false, true);
}

function output(executable, arguments_) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, arguments_, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (data) => (stdout += data));
    child.stderr.on("data", (data) => (stderr += data));
    child.once("error", reject);
    child.once("close", (code) => {
      if (code === 0) resolve(stdout);
      else reject(new Error(`${executable} ${arguments_.join(" ")} failed: ${stderr.trim()}`));
    });
  });
}

function run(executable, arguments_, inherited = false, allowFailure = false) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, arguments_, { stdio: inherited ? "inherit" : "ignore" });
    if (inherited) testProcess = child;
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (inherited) testProcess = undefined;
      if (code === 0 || allowFailure) resolve(code ?? 1);
      else reject(new Error(`${executable} exited with ${signal ?? code}`));
    });
  });
}
