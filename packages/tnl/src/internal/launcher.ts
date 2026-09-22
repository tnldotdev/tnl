import { constants, accessSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import process from "node:process";
import { nativeTargets } from "./native-targets.js";

const require = createRequire(import.meta.url);
const launcherManifest = new URL("../../package.json", import.meta.url);

const nativePackages = new Map(
  nativeTargets.map(({ platform, architecture, packageName }) => [
    `${platform}-${architecture}`,
    packageName,
  ]),
);

interface NativeBinaryOptions {
  readonly architecture?: NodeJS.Architecture;
  readonly platform?: NodeJS.Platform;
  readonly resolve?: (specifier: string) => string;
}

interface PackageManifest {
  readonly version: string;
}

export function nativePackageName(
  platform: NodeJS.Platform,
  architecture: NodeJS.Architecture,
): string {
  const packageName = nativePackages.get(`${platform}-${architecture}`);
  if (packageName === undefined) {
    throw new Error(
      `unsupported platform ${platform}-${architecture}; tnl supports macOS and Linux on arm64 and x64`,
    );
  }
  return packageName;
}

export function resolveNativeBinary(options: NativeBinaryOptions = {}): string {
  const {
    architecture = process.arch,
    platform = process.platform,
    resolve = require.resolve,
  } = options;
  const packageName = nativePackageName(platform, architecture);
  let nativeManifestPath: string;
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

function readManifest(file: string | URL): PackageManifest {
  const value = JSON.parse(readFileSync(file, "utf8")) as unknown;
  if (
    value === null ||
    typeof value !== "object" ||
    !("version" in value) ||
    typeof value.version !== "string"
  ) {
    throw new Error("package manifest has an invalid shape");
  }
  return { version: value.version };
}
