import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const versionPattern =
  /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;

function parseVersion(value: string): {
  release: readonly [bigint, bigint, bigint];
  prerelease: readonly (bigint | string)[];
} {
  const match = versionPattern.exec(value);
  if (!match) throw new Error(`invalid release version ${value}`);
  const [, major, minor, patch, prereleaseText] = match;
  if (major === undefined || minor === undefined || patch === undefined) {
    throw new Error(`invalid release version ${value}`);
  }
  const prerelease = (prereleaseText?.split(".") ?? []).map((identifier) => {
    if (!/^[0-9]+$/.test(identifier)) return identifier;
    if (identifier.length > 1 && identifier.startsWith("0"))
      throw new Error(`numeric prerelease identifier has a leading zero: ${identifier}`);
    return BigInt(identifier);
  });
  return { release: [BigInt(major), BigInt(minor), BigInt(patch)], prerelease };
}

export function assertReleaseVersion(version: string): void {
  parseVersion(version);
}

export function versionFromTag(tag: string): string {
  if (!tag.startsWith("v") || tag.length > 128) throw new Error(`invalid release tag ${tag}`);
  const version = tag.slice(1);
  assertReleaseVersion(version);
  return version;
}

export function compareReleaseVersions(left: string, right: string): number {
  const a = parseVersion(left);
  const b = parseVersion(right);
  for (const index of [0, 1, 2] as const) {
    if (a.release[index] !== b.release[index]) return a.release[index] < b.release[index] ? -1 : 1;
  }
  if (a.prerelease.length === 0 || b.prerelease.length === 0) {
    if (a.prerelease.length === b.prerelease.length) return 0;
    return a.prerelease.length === 0 ? 1 : -1;
  }
  for (let index = 0; index < Math.max(a.prerelease.length, b.prerelease.length); index++) {
    const leftPart = a.prerelease[index];
    const rightPart = b.prerelease[index];
    if (leftPart === undefined || rightPart === undefined) {
      return leftPart === rightPart ? 0 : leftPart === undefined ? -1 : 1;
    }
    if (leftPart === rightPart) continue;
    if (typeof leftPart === "bigint" && typeof rightPart === "bigint") {
      return leftPart < rightPart ? -1 : 1;
    }
    if (typeof leftPart !== typeof rightPart) return typeof leftPart === "bigint" ? -1 : 1;
    return leftPart < rightPart ? -1 : 1;
  }
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const tag = process.argv[2];
  if (!tag) throw new Error("usage: node scripts/release-version.ts TAG");
  process.stdout.write(versionFromTag(tag));
}
import { installToolFailureHandler } from "./errors.ts";
installToolFailureHandler(import.meta, "tool.input_invalid");
