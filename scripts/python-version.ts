import { assertReleaseVersion } from "./release-version.ts";

/** Translate the root tnl tag into the version published for all Python wheels. */
export function pythonVersion(release: string): string {
  assertReleaseVersion(release);
  if (/^0\.0\.0-SNAPSHOT-[0-9a-f]{8,40}$/.test(release)) return "0.0.0.dev0";
  const match = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-rc\.(0|[1-9][0-9]*))?$/.exec(
    release,
  );
  if (match === null) throw new Error(`unsupported Python release version ${release}`);
  const [, major, minor, patch, rc] = match;
  return `${major}.${minor}.${patch}${rc === undefined ? "" : `rc${rc}`}`;
}
