import { expect, test } from "vitest";
import { assertReleaseVersion, compareReleaseVersions, versionFromTag } from "./release-version.ts";

test("accepts stable and snapshot tags but rejects versions that cannot be released", () => {
  expect(versionFromTag("v1.2.3")).toBe("1.2.3");
  expect(versionFromTag("v0.0.0-SNAPSHOT-abcd123")).toBe("0.0.0-SNAPSHOT-abcd123");
  expect(() => assertReleaseVersion("1.2.3-rc.01")).toThrow("leading zero");
  for (const tag of [
    "1.2.3",
    "v01.2.3",
    "v1.2.3+build",
    "v1.2.3-rc.01",
    `v1.2.3-${"a".repeat(122)}`,
  ]) {
    expect(() => versionFromTag(tag)).toThrow();
  }
});

test("orders stable, prerelease, and large numeric versions", () => {
  for (const [left, right] of [
    ["1.2.3-rc.9", "1.2.3-rc.10"],
    ["1.2.3-rc.10", "1.2.3-rc.10.1"],
    ["1.2.3-1", "1.2.3-beta"],
    ["1.2.3-rc.1", "1.2.3"],
    ["1.2.3", "1.2.4"],
    ["9999999999999999999.0.0", "10000000000000000000.0.0"],
  ] as const) {
    expect(compareReleaseVersions(left, right)).toBe(-1);
    expect(compareReleaseVersions(right, left)).toBe(1);
  }
  expect(compareReleaseVersions("1.2.3-rc.1", "1.2.3-rc.1")).toBe(0);
});
