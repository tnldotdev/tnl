import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  copyFile,
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import path from "node:path";
import { promisify } from "node:util";
import { build, createNitro, prepare } from "nitropack";
import * as z from "zod";

const run = promisify(execFile);
const root = path.resolve(import.meta.dirname, "../..");
const [outputArgument, hostBinary, linuxBinary, workloadManifest] = process.argv.slice(2);
assert(
  outputArgument && hostBinary && linuxBinary && workloadManifest,
  "pass output, host binary, linux-x64 binary and generated workload manifest",
);
assert.equal(process.versions.node, "24.20.0");
const output = path.resolve(outputArgument);
const staging = await mkdtemp(path.join(tmpdir(), "tnl-vercel-build-"));
const legal = ["LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"];
const manifestSchema = z.looseObject({ name: z.string(), version: z.string() });
const launcher = manifestSchema.parse(
  JSON.parse(await readFile(path.join(root, "packages/ts/package.json"), "utf8")),
);
const hostName = `@tnldotdev/tnl-${process.platform}-${process.arch}`;
const linuxName = "@tnldotdev/tnl-linux-x64";
const natives = new Map([
  [hostName, hostBinary],
  [linuxName, linuxBinary],
]);
const hashes = new Map<string, string>();

try {
  await mkdir(output, { recursive: true });
  for (const file of [
    "qualification.json",
    "host-files.json",
    "linux-x64-files.json",
    "host-invocation.json",
    "linux-x64-invocation.json",
  ])
    await rm(path.join(output, file), { force: true });
  const tarballs: Record<string, string> = {};
  for (const [name, binary] of natives) {
    const platform = name === linuxName ? "linux-x64" : `${process.platform}-${process.arch}`;
    const stage = path.join(staging, platform);
    await mkdir(path.join(stage, "bin"), { recursive: true });
    await copyFile(binary, path.join(stage, "bin/tnl"));
    await chmod(path.join(stage, "bin/tnl"), 0o755);
    for (const file of legal) await copyFile(path.join(root, file), path.join(stage, file));
    const template = manifestSchema.parse(
      JSON.parse(
        await readFile(path.join(root, `packages/ts/native/${platform}/package.json`), "utf8"),
      ),
    );
    await json(path.join(stage, "package.json"), {
      ...template,
      version: launcher.version,
      publishConfig: { executableFiles: ["bin/tnl"] },
    });
    hashes.set(name, sha256(await readFile(binary)));
    tarballs[name] = `file:${await pack(stage)}`;
  }
  const stage = path.join(staging, "launcher");
  await mkdir(stage);
  await cp(path.join(root, "packages/ts/dist"), path.join(stage, "dist"), { recursive: true });
  for (const file of legal) await copyFile(path.join(root, file), path.join(stage, file));
  await json(path.join(stage, "package.json"), {
    ...launcher,
    scripts: undefined,
    optionalDependencies: Object.fromEntries(
      [...natives.keys()].map((name) => [name, launcher.version]),
    ),
  });
  tarballs[launcher.name] = `file:${await pack(stage)}`;
  const consumer = path.join(staging, "consumer");
  await mkdir(path.join(consumer, "server/routes"), { recursive: true });
  await json(path.join(consumer, "package.json"), {
    private: true,
    type: "module",
    dependencies: { ...tarballs, h3: "1.15.11", pg: "8.23.1" },
  });
  await writeFile(
    path.join(consumer, "pnpm-workspace.yaml"),
    `packages: []\nautoInstallPeers: false\nsupportedArchitectures:\n  os: [current, linux]\n  cpu: [current, x64]\noverrides:\n${[...natives.keys()].map((name) => `  '${name}': '${tarballs[name]}'`).join("\n")}\n`,
  );
  await run("pnpm", ["install", "--ignore-scripts"], { cwd: consumer, timeout: 120_000 });
  const { stdout: managerVersion } = await run("pnpm", ["--version"], { cwd: consumer });
  assert.equal(managerVersion.trim(), "11.25.0");
  await copyFile(
    path.join(import.meta.dirname, "function.ts"),
    path.join(consumer, "server/routes/check.ts"),
  );

  for (const [variant, nativeName] of [
    ["host", hostName],
    ["linux-x64", linuxName],
  ] as const) {
    const destination = path.join(output, variant, ".vercel/output");
    await rm(path.join(output, variant), { recursive: true, force: true });
    // native resolution is dynamic. explicitly trace its metadata, executable and
    // legal files, as well as the launcher's non-code files. Nitro owns emission.
    const traceInclude = [];
    for (const name of [launcher.name, nativeName]) {
      const installed = await realpath(path.join(consumer, "node_modules", name));
      for (const file of [
        ...legal,
        "package.json",
        ...(name === nativeName
          ? ["bin/tnl"]
          : ["dist/third-party-licenses.txt", "dist/index.cjs"]),
      ])
        traceInclude.push(path.join(installed, file));
    }
    for (const name of ["undici", "pg", "@vercel/oidc"]) {
      const base =
        name !== "pg"
          ? await realpath(path.join(consumer, "node_modules", launcher.name))
          : consumer;
      const require = createRequire(path.join(base, "package.json"));
      traceInclude.push(
        path.join(
          name === "@vercel/oidc"
            ? path.resolve(path.dirname(require.resolve(name)), "..")
            : path.dirname(require.resolve(`${name}/package.json`)),
          "LICENSE",
        ),
      );
    }
    const nitro = await createNitro({
      rootDir: consumer,
      srcDir: path.join(consumer, "server"),
      workspaceDir: consumer,
      preset: "vercel",
      compatibilityDate: "2026-10-20",
      output: { dir: destination },
      vercel: { functions: { runtime: "nodejs24.x" } },
      rollupConfig: { external: traceInclude },
      externals: {
        external: ["@tnldotdev/tnl", "undici", "pg"],
        traceInclude,
        traceOptions: {
          ignore: (file) =>
            [...natives.keys()].some((name) => name !== nativeName && file.includes(`${name}/`)),
        },
      },
    });
    try {
      await prepare(nitro);
      await build(nitro);
    } finally {
      await nitro.close();
    }
    const generated = path.join(destination, "functions/__fallback.func/.tnl/generated");
    await mkdir(generated, { recursive: true });
    await copyFile(workloadManifest, path.join(generated, "workloads.json"));
    await verify(destination, nativeName, variant);
  }
  await json(path.join(output, "qualification.json"), {
    builder: "nitropack@2.13.5",
    node: process.versions.node,
    packageManager: "pnpm@11.25.0",
    host: `${process.platform}-${process.arch}`,
    linux: "linux-x64 packaging; runtime evidence is in linux-x64-invocation.json when selected",
    nativeSha256: Object.fromEntries(hashes),
  });
} finally {
  // neither the consumer install nor its source is available during invocation.
  await rm(staging, { recursive: true, force: true });
}

async function verify(destination: string, nativeName: string, variant: string) {
  const config = z
    .object({
      version: z.literal(3),
      routes: z.array(z.looseObject({ dest: z.optional(z.string()) })),
    })
    .parse(JSON.parse(await readFile(path.join(destination, "config.json"), "utf8")));
  assert(config.routes.some((route) => route.dest === "/__fallback"));
  const fn = path.join(destination, "functions/__fallback.func");
  const vc = z
    .object({
      runtime: z.literal("nodejs24.x"),
      handler: z.literal("index.mjs"),
      launcherType: z.literal("Nodejs"),
    })
    .parse(JSON.parse(await readFile(path.join(fn, ".vc-config.json"), "utf8")));
  await stat(path.join(fn, vc.handler));
  for (const name of [launcher.name, nativeName, "undici", "pg", "@vercel/oidc"]) {
    const manifest = manifestSchema.parse(
      JSON.parse(await readFile(path.join(fn, "node_modules", name, "package.json"), "utf8")),
    );
    assert.equal(manifest.name, name);
    if (name.startsWith("@tnldotdev/")) {
      assert.equal(manifest.version, launcher.version);
      for (const file of legal)
        assert.deepEqual(
          await readFile(path.join(fn, "node_modules", name, file)),
          await readFile(path.join(root, file)),
        );
    } else {
      assert.equal(
        manifest.version,
        { undici: "7.30.1", pg: "8.23.1", "@vercel/oidc": "4.0.2" }[name],
      );
      assert((await stat(path.join(fn, "node_modules", name, "LICENSE"))).size > 0);
    }
  }
  const binary = path.join(fn, "node_modules", nativeName, "bin/tnl");
  assert.notEqual((await stat(binary)).mode & 0o111, 0);
  const data = await readFile(binary);
  assert.equal(sha256(data), hashes.get(nativeName));
  if (variant === "linux-x64") {
    assert.equal(data.subarray(0, 4).toString("hex"), "7f454c46");
    assert.equal(data[4], 2, "expected ELF64");
    assert.equal(data.readUInt16LE(18), 62, "expected x86-64");
  }
  const files = await readdir(fn, { recursive: true });
  for (const file of files) {
    assert(
      !file
        .split(path.sep)
        .some(
          (part) =>
            [
              ".git",
              "client-state",
              "handle.json",
              "expired.json",
              "v1.db",
              "tnl.json",
              "tnl.yml",
              "tnl.yaml",
              "tnl.config.ts",
            ].includes(part) ||
            part === ".env" ||
            part.startsWith(".env."),
        ),
      `private source/state in artifact: ${file}`,
    );
    assert(
      ![...natives.keys()].some((name) => name !== nativeName && file.includes(`${name}/`)),
      `wrong-platform native file: ${file}`,
    );
    const entry = path.join(fn, file);
    if ((await lstat(entry)).isSymbolicLink()) {
      const target = await realpath(entry);
      assert(target.startsWith(`${fn}${path.sep}`), `escaping artifact symlink: ${file}`);
    }
  }
  assert.deepEqual(
    await readFile(path.join(fn, ".tnl/generated/workloads.json")),
    await readFile(workloadManifest ?? ""),
  );
  assert.deepEqual(files.filter((file) => file.startsWith(".tnl/")).sort(), [
    ".tnl/generated",
    ".tnl/generated/workloads.json",
  ]);
  await json(path.join(output, `${variant}-files.json`), files.sort());
}

async function pack(cwd: string): Promise<string> {
  const { stdout } = await run("pnpm", ["pack", "--json", "--pack-destination", staging], {
    cwd,
    timeout: 30_000,
  });
  const result = z.object({ filename: z.string() }).parse(JSON.parse(stdout));
  return path.resolve(staging, result.filename);
}
function sha256(data: Uint8Array) {
  return createHash("sha256").update(data).digest("hex");
}
async function json(file: string, value: unknown) {
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`);
}
