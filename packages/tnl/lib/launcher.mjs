import { constants, accessSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import process from "node:process";

const require = createRequire(import.meta.url);
const launcherManifest = new URL("../package.json", import.meta.url);

const nativePackages = new Map([
  ["darwin-arm64", "@tnldotdev/tnl-darwin-arm64"],
  ["darwin-x64", "@tnldotdev/tnl-darwin-x64"],
  ["linux-arm64", "@tnldotdev/tnl-linux-arm64"],
  ["linux-x64", "@tnldotdev/tnl-linux-x64"],
]);

export function nativePackageName(platform, architecture) {
  const packageName = nativePackages.get(`${platform}-${architecture}`);
  if (packageName === undefined) {
    throw new Error(
      `unsupported platform ${platform}-${architecture}; tnl supports macOS and Linux on arm64 and x64`,
    );
  }
  return packageName;
}

export function resolveNativeBinary({
  architecture = process.arch,
  platform = process.platform,
  resolve = require.resolve,
} = {}) {
  const packageName = nativePackageName(platform, architecture);
  let nativeManifestPath;
  try {
    nativeManifestPath = resolve(`${packageName}/package.json`);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "MODULE_NOT_FOUND") {
      throw new Error(
        `${packageName} is missing; reinstall @tnldotdev/tnl without disabling optional dependencies`,
        { cause: error },
      );
    }
    throw error;
  }

  const mainManifest = readManifest(launcherManifest);
  const nativeManifest = readManifest(nativeManifestPath);
  if (nativeManifest.version !== mainManifest.version) {
    throw new Error(
      `${packageName}@${String(nativeManifest.version)} does not match @tnldotdev/tnl@${String(mainManifest.version)}`,
    );
  }

  const binary = path.join(path.dirname(nativeManifestPath), "bin", "tnl");
  try {
    accessSync(binary, constants.X_OK);
  } catch (error) {
    throw new Error(`${packageName} does not contain an executable tnl binary`, { cause: error });
  }
  return binary;
}

function readManifest(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}
