import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmod, copyFile, cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import * as z from "zod";
import { nativePackageName } from "../../dist/internal/launcher.js";

// run from the prepared project's directory with TNL_CONNECTION_HANDLE and the
// application's DB_USER, DB_PASSWORD and DB_NAME. the caller owns native cleanup.
const binary = process.argv[2];
const protocol = process.argv[3] ?? "postgres";
assert(
  binary && path.isAbsolute(binary),
  "pass the real native fixture binary as an absolute path",
);
assert(process.env.TNL_CONNECTION_HANDLE, "prepare a native connection handle first");
const run = promisify(execFile);
const packageRoot = path.resolve(import.meta.dirname, "../..");
const root = path.resolve(packageRoot, "../..");
const manifestSchema = z.looseObject({ name: z.string(), version: z.string() });
const launcher = manifestSchema.parse(
  JSON.parse(await readFile(path.join(packageRoot, "package.json"), "utf8")) as unknown,
);
const workspace = z
  .looseObject({ devDependencies: z.record(z.string(), z.string()) })
  .parse(JSON.parse(await readFile(path.join(root, "package.json"), "utf8")) as unknown);
const directory = await mkdtemp(path.join(tmpdir(), "tnl-installed-drizzle-"));
let stage = "native packaging";
try {
  const nativeName = nativePackageName(process.platform, process.arch);
  const nativeStage = path.join(directory, "native");
  const launcherStage = path.join(directory, "launcher");
  const consumer = path.join(directory, "consumer");
  await mkdir(path.join(nativeStage, "bin"), { recursive: true });
  await mkdir(launcherStage);
  await mkdir(consumer);
  await copyFile(binary, path.join(nativeStage, "bin/tnl"));
  await chmod(path.join(nativeStage, "bin/tnl"), 0o755);
  await writeFile(
    path.join(nativeStage, "package.json"),
    JSON.stringify({
      name: nativeName,
      version: launcher.version,
      os: [process.platform],
      cpu: [process.arch],
      files: ["bin/tnl"],
      publishConfig: { executableFiles: ["bin/tnl"] },
    }),
  );
  const pack = async (cwd: string): Promise<string> => {
    const tarball = path.join(directory, `${path.basename(cwd)}.tgz`);
    await run("pnpm", ["pack", "--out", tarball], {
      cwd,
      timeout: 30_000,
    });
    return tarball;
  };
  const nativeTarball = await pack(nativeStage);
  stage = "sdk packaging";
  await cp(path.join(packageRoot, "dist"), path.join(launcherStage, "dist"), { recursive: true });
  await writeFile(
    path.join(launcherStage, "package.json"),
    JSON.stringify({
      ...launcher,
      scripts: {},
      optionalDependencies: { [nativeName]: launcher.version },
    }),
  );
  for (const file of ["LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"])
    await copyFile(path.join(root, file), path.join(launcherStage, file));
  const tarball = await pack(launcherStage);
  await writeFile(
    path.join(consumer, "package.json"),
    JSON.stringify({
      private: true,
      type: "module",
      dependencies: {
        "@tnldotdev/tnl": `file:${tarball}`,
        [nativeName]: `file:${nativeTarball}`,
        "drizzle-kit": workspace.devDependencies["drizzle-kit"],
        "drizzle-orm": workspace.devDependencies["drizzle-orm"],
        pg: workspace.devDependencies.pg,
        postgres: workspace.devDependencies.postgres,
        mysql: workspace.devDependencies.mysql,
        mysql2: workspace.devDependencies.mysql2,
        zod: workspace.devDependencies.zod,
      },
    }),
  );
  await writeFile(
    path.join(consumer, "pnpm-workspace.yaml"),
    `overrides:\n  '${nativeName}': 'file:${nativeTarball}'\n`,
  );
  stage = "dependency installation";
  await run("pnpm", ["install", "--ignore-scripts"], {
    cwd: consumer,
    timeout: 120_000,
    maxBuffer: 1024 * 1024,
  });
  if (protocol.endsWith("-drivers")) {
    stage = "database drivers";
    const fixture = path.join(consumer, "database-drivers.ts");
    await copyFile(path.join(import.meta.dirname, "database-drivers.ts"), fixture);
    const { stdout, stderr } = await run(process.execPath, [fixture, protocol], {
      cwd: consumer,
      timeout: 60_000,
      maxBuffer: 1024 * 1024,
    }).catch((cause: unknown) => {
      if (
        typeof cause === "object" &&
        cause !== null &&
        "stdout" in cause &&
        typeof cause.stdout === "string"
      ) {
        const line = cause.stdout.trim().split("\n").at(-1);
        if (line) {
          const failure = z
            .object({
              phase: z.string().regex(/^[a-z0-9 ]{1,80}$/),
              code: z.string().regex(/^(?:[A-Z0-9_]{1,64}|sdk\.[a-z_]{1,64})$/),
            })
            .parse(JSON.parse(line));
          process.stdout.write(JSON.stringify(failure) + "\n");
        }
      }
      throw new Error("installed database driver check failed");
    });
    // pg 8.23's own cancel() reads its deprecated activeQuery getter. allow only
    // that known method warning; ordinary connection-option warnings still fail.
    const warnings =
      protocol === "postgres-drivers"
        ? stderr.replace(
            /^\(node:\d+\) DeprecationWarning: Client\.activeQuery is deprecated and will be removed in pg@9\.0\n\(Use `node --trace-deprecation \.\.\.` to show where the warning was created\)\n$/,
            "",
          )
        : stderr;
    assert.equal(warnings, "", "ordinary driver settings must not produce option warnings");
    process.stdout.write(stdout);
  } else if (protocol !== "postgres") {
    stage = "native runtime";
    const fixture = path.join(consumer, "native-runtime.ts");
    await copyFile(path.join(import.meta.dirname, "native-runtime.ts"), fixture);
    await run(process.execPath, [fixture, protocol], { cwd: consumer, timeout: 60_000 });
  } else {
    stage = "drizzle config";
    await copyFile(
      path.join(import.meta.dirname, "drizzle.config.ts"),
      path.join(consumer, "drizzle.config.ts"),
    );
    await cp(path.join(process.cwd(), "migrations"), path.join(consumer, "migrations"), {
      recursive: true,
    });
    const verification = path.join(consumer, "verify.mjs");
    await writeFile(
      verification,
      `
    import assert from "node:assert/strict";
    import {createRequire} from "node:module";
    import {tnl, TnlError} from "@tnldotdev/tnl";
    const cjs = createRequire(import.meta.url)("@tnldotdev/tnl");
    assert.equal(cjs.TnlError, TnlError);
    for (const runtime of [tnl, cjs.tnl]) {
      const handle = runtime.connect("database");
      const synchronous = {...handle};
      assert.deepEqual(Object.keys(synchronous), ["host", "port", "ssl"]);
      assert.equal(synchronous.host, "127.0.0.1");
      assert.equal(synchronous.ssl.servername, runtime.services.database.hostname);
      assert.equal(synchronous.ssl.rejectUnauthorized, true);
      assert.equal(synchronous.ssl.cert, undefined);
      assert.equal(synchronous.ssl.key, undefined);
      const [first, second] = await Promise.all([handle, Promise.resolve(handle)]);
      assert.deepEqual(first, synchronous);
      assert.deepEqual(second, synchronous);
      assert.equal(first.then, undefined);
      assert(Object.isFrozen(first) && Object.isFrozen(first.ssl));
    }
  `,
    );
    await run(process.execPath, [verification], { cwd: consumer, timeout: 60_000 });
    // drizzle kit loads this ordinary typescript config through its commonjs
    // loader. there is no module cache injection, custom loader or top-level await.
    await run("pnpm", ["exec", "drizzle-kit", "migrate"], {
      cwd: consumer,
      timeout: 60_000,
      maxBuffer: 1024 * 1024,
    });
    // drizzle can print a failure and still exit zero. check the table created by
    // the native integration fixture's migration through the installed SDK and pg.
    await writeFile(
      verification,
      `
    import assert from "node:assert/strict";
    import {tnl} from "@tnldotdev/tnl";
    import pg from "pg";
    const client = new pg.Client({
      ...await tnl.connect("database"),
      user: process.env.DB_USER ?? "app",
      password: process.env.DB_PASSWORD ?? "application-owned",
      database: process.env.DB_NAME ?? "app",
    });
    await client.connect();
    try {
      const result = await client.query("SELECT to_regclass('public.sdk_migration')::text AS name");
      assert.equal(result.rows[0]?.name, "sdk_migration");
    } finally {
      await client.end();
    }
  `,
    );
    await run(process.execPath, [verification], { cwd: consumer, timeout: 60_000 });
  }
  process.stdout.write("installed package connection checks passed\n");
} catch {
  // driver and subprocess output may contain application account details.
  throw new Error(`installed pnpm package verification failed during ${stage}`);
} finally {
  await rm(directory, { recursive: true, force: true });
}
