import * as core from "@actions/core";
import { spawn } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { build } from "esbuild";
import { nativeJSON } from "../src/native.ts";

const operation = process.argv[2];
if (operation === "prepare") {
  const parent = await realpath(process.env.RUNNER_TEMP ?? "");
  const root = await mkdtemp(path.join(parent, "tnl-action-workflow-"));
  await chmod(root, 0o700);
  const project = path.join(root, "project");
  await mkdir(project, { mode: 0o700 });
  await writeFile(path.join(project, "fixture.json"), "{}");
  const binary = path.join(root, "fixture-tnl");
  await build({
    entryPoints: [new URL("./native-fixture.ts", import.meta.url).pathname],
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node22",
    outfile: binary,
    banner: { js: `#!${process.execPath}` },
  });
  await chmod(binary, 0o700);
  const child = spawn(binary, ["oidc"], {
    cwd: project,
    detached: true,
    stdio: ["ignore", "pipe", "ignore"],
  });
  const chunks = [];
  for await (const chunk of child.stdout) chunks.push(Buffer.from(chunk));
  child.unref();
  const response = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { url: string };
  core.setOutput("root", root);
  core.setOutput("project", project);
  core.setOutput("binary", binary);
  core.setOutput("oidc", response.url);
} else if (operation === "observe") {
  const handle = process.env.TNL_CONNECTION_HANDLE;
  if (!handle) throw new Error("action did not export the private handle");
  const session = path.dirname(path.dirname(handle));
  const saved = JSON.parse(await readFile(path.join(session, "cleanup.json"), "utf8")) as {
    binary: string;
  };
  const result = await nativeJSON(saved.binary, ["status", "--handle", handle], {
    cwd: session,
    timeout: 5000,
  });
  if (
    typeof result !== "object" ||
    result === null ||
    !("state" in result) ||
    result.state !== "ready"
  )
    throw new Error("owner did not survive the action step");
  const projectRuntime = JSON.parse(process.env.TNL_PROJECT_RUNTIME ?? "null") as {
    services?: { database?: { port: number } };
  } | null;
  if (projectRuntime?.services?.database?.port !== 5432)
    throw new Error("action did not export public runtime JSON");
  core.info("native fixture is ready in a later job step");
} else if (operation === "remove-original") {
  await rm(path.join(process.env.FIXTURE_ROOT ?? "", "fixture-tnl"));
} else if (operation === "stop-oidc") {
  const project = path.join(process.env.FIXTURE_ROOT ?? "", "project");
  const saved = JSON.parse(await readFile(path.join(project, "oidc.json"), "utf8")) as {
    port: number;
    key: string;
  };
  const response = await fetch(`http://127.0.0.1:${saved.port}/stop`, {
    method: "POST",
    headers: { Authorization: `Bearer ${saved.key}` },
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw new Error("could not stop the owned OIDC fixture");
} else throw new Error("unknown workflow fixture operation");
