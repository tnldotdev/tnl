import { readFile } from "node:fs/promises";
import { expect, test } from "vitest";
import { nativeTargets } from "../../packages/ts/src/internal/native/native-targets.ts";
import { legalFiles } from "./release-artifacts.ts";
import { wheelProject, wheelTag } from "./pack-python-wheels.ts";
import { pythonVersion } from "./python-version.ts";

test.each(["1.0.0", "1.2.3-rc.4", "1.0.0-SNAPSHOT-abcdef1"])(
  "stages the current Python project for release %s",
  async (release) => {
    const config = await readFile(
      new URL("../../packages/py/pyproject.toml", import.meta.url),
      "utf8",
    );
    for (const target of nativeTargets) {
      const staged = wheelProject(config, pythonVersion(release), target);
      expect(staged.match(/^version = "([^"]+)"$/m)?.[1]).toBe(pythonVersion(release));
      expect(staged).toContain(`license-files = ${JSON.stringify(legalFiles)}`);
      expect(staged).toContain(`tag = "py3-none-${wheelTag(target)}"`);
    }
  },
);

test("rejects a stale development-version marker instead of silently mislabeling wheels", () => {
  const target = nativeTargets[0];
  expect(target).toBeDefined();
  if (target === undefined) throw new Error("missing native target");
  expect(() => wheelProject('version = "2.0.0.dev0"', "2.0.0", target)).toThrow(
    "Python project development version changed",
  );
});
