import { expect, test } from "vitest";
import { pythonVersion } from "./python-version.ts";

test("maps signed root release versions to PEP 440 without inventing prereleases", () => {
  expect(pythonVersion("0.1.0-rc.40")).toBe("0.1.0rc40");
  expect(pythonVersion("1.2.3")).toBe("1.2.3");
  expect(pythonVersion("0.0.0-SNAPSHOT-abcdef12")).toBe("0.0.0.dev0");
  expect(() => pythonVersion("0.1.0-beta.2")).toThrow("unsupported Python release version");
  expect(() => pythonVersion("0.1.0-rc.01")).toThrow();
});
