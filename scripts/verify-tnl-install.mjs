import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const packageDirectoryArgument = process.argv[2];
assert(packageDirectoryArgument, "usage: node scripts/verify-tnl-install.mjs PACKAGE_DIRECTORY");

const packageDirectory = path.resolve(packageDirectoryArgument);
const metadata = JSON.parse(
  await readFile(path.join(packageDirectory, "tnl-npm-packages.json"), "utf8"),
);
const nativePackageName = `@tnldotdev/tnl-${process.platform}-${process.arch}`;
exactlyOne(
  metadata.packages.filter((entry) => entry.name === nativePackageName),
  `${process.platform}-${process.arch} native package`,
);

const registry = await startRegistry();
try {
  for (const packageManager of ["npm", "pnpm"]) {
    await verifyPackageManager(packageManager, registry.url);
  }
} finally {
  await registry.close();
}

async function verifyPackageManager(packageManager, registryURL) {
  const consumer = await mkdtemp(path.join(tmpdir(), `tnl-${packageManager}-consumer-`));
  try {
    await writeFile(
      path.join(consumer, "package.json"),
      `${JSON.stringify(
        {
          dependencies: { "@tnldotdev/tnl": metadata.version },
          private: true,
        },
        null,
        2,
      )}\n`,
    );
    if (packageManager === "npm") {
      await run(
        "npm",
        [
          "install",
          "--cache",
          path.join(consumer, ".npm-cache"),
          "--ignore-scripts",
          "--no-audit",
          "--no-fund",
          "--registry",
          registryURL,
        ],
        consumer,
      );
    } else {
      await run(
        "pnpm",
        [
          "install",
          "--ignore-scripts",
          "--registry",
          registryURL,
          "--store-dir",
          path.join(consumer, ".pnpm-store"),
        ],
        consumer,
      );
    }

    const executable = path.join(consumer, "node_modules", ".bin", "tnl");
    const { stdout } = await run(executable, ["version"], consumer);
    assert.equal(stdout.trim(), `tnl ${metadata.version} (${metadata.commit})`);
    await assert.rejects(
      () => readFile(path.join(consumer, "node_modules", ".bin", "tnld")),
      /ENOENT/,
    );
  } finally {
    await rm(consumer, { force: true, recursive: true });
  }
}

async function startRegistry() {
  const packages = new Map();
  const tarballs = new Map();
  for (const entry of metadata.packages) {
    const tarballPath = path.join(packageDirectory, entry.tarball);
    const { stdout } = await execFileAsync("tar", ["-xOzf", tarballPath, "package/package.json"], {
      maxBuffer: 1024 * 1024,
    });
    const manifest = JSON.parse(stdout);
    assert.equal(manifest.name, entry.name);
    assert.equal(manifest.version, metadata.version);
    const tarballPathname = `/tarballs/${entry.tarball}`;
    packages.set(entry.name, { entry, manifest, tarballPathname });
    tarballs.set(tarballPathname, tarballPath);
  }

  const server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", "http://registry.invalid");
      const tarball = tarballs.get(url.pathname);
      if (tarball !== undefined) {
        response.setHeader("Content-Type", "application/octet-stream");
        response.end(await readFile(tarball));
        return;
      }

      const packageName = decodeURIComponent(url.pathname.slice(1));
      const package_ = packages.get(packageName);
      if (package_ === undefined) {
        response.statusCode = 404;
        response.end(JSON.stringify({ error: "not found" }));
        return;
      }
      const address = server.address();
      assert(typeof address === "object" && address !== null);
      const versionManifest = {
        ...package_.manifest,
        dist: {
          integrity: package_.entry.integrity,
          tarball: `http://127.0.0.1:${address.port}${package_.tarballPathname}`,
        },
      };
      response.setHeader("Content-Type", "application/json");
      response.end(
        JSON.stringify({
          name: packageName,
          "dist-tags": { latest: metadata.version },
          versions: { [metadata.version]: versionManifest },
        }),
      );
    } catch (error) {
      response.statusCode = 500;
      response.end(error instanceof Error ? error.message : String(error));
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert(typeof address === "object" && address !== null);
  return {
    url: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}

async function run(command, arguments_, cwd) {
  try {
    return await execFileAsync(command, arguments_, {
      cwd,
      maxBuffer: 10 * 1024 * 1024,
    });
  } catch (error) {
    if (typeof error === "object" && error !== null) {
      if ("stdout" in error && error.stdout) {
        process.stdout.write(String(error.stdout));
      }
      if ("stderr" in error && error.stderr) {
        process.stderr.write(String(error.stderr));
      }
    }
    throw error;
  }
}

function exactlyOne(values, description) {
  assert.equal(values.length, 1, `expected exactly one ${description}`);
  return values[0];
}
