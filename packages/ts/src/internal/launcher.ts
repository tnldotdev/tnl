import { constants, accessSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import process from "node:process";
import { nativeTargets } from "./native-targets.js";
import { TnlError } from "../errors.js";

const require = createRequire(import.meta.url);
const launcherManifest = new URL("../../package.json", import.meta.url);
const packageVersionPattern =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

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
    throw new TnlError("sdk.native_unsupported");
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
      throw new TnlError("sdk.native_missing", { cause: error });
    }
    throw new TnlError("sdk.native_invalid", { cause: error });
  }

  const mainManifest = readManifest(launcherManifest, "@tnldotdev/tnl");
  const nativeManifest = readManifest(nativeManifestPath, packageName);
  if (nativeManifest.version !== mainManifest.version) {
    throw new TnlError("sdk.native_invalid");
  }

  const binary = path.join(path.dirname(nativeManifestPath), "bin", "tnl");
  try {
    accessSync(binary, constants.X_OK);
  } catch (error) {
    throw new TnlError("sdk.native_invalid", { cause: error });
  }
  return binary;
}

function readManifest(file: string | URL, _packageName: string): PackageManifest {
  let serialized: string;
  try {
    serialized = readFileSync(file, "utf8");
  } catch (error) {
    throw new TnlError("sdk.native_invalid", { cause: error });
  }
  let value: unknown;
  try {
    value = JSON.parse(serialized) as unknown;
  } catch (error) {
    throw new TnlError("sdk.native_invalid", { cause: error });
  }
  try {
    return parseManifest(value);
  } catch (error) {
    throw new TnlError("sdk.native_invalid", { cause: error });
  }
}

function parseManifest(value: unknown): PackageManifest {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    !("version" in value) ||
    typeof value.version !== "string" ||
    value.version.length > 256 ||
    !packageVersionPattern.test(value.version)
  ) {
    throw new TypeError("package manifest version must be a valid semantic version");
  }
  return { version: value.version };
}
