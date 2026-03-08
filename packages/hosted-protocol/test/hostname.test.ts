import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { canonicalizeAuthority, canonicalizeHostname, HostnameError } from "../src/hostname.js";

interface Fixture {
  version: number;
  cases: FixtureCase[];
}

interface FixtureCase {
  name: string;
  context: "hostname" | "authority";
  input: string;
  canonical?: string;
  error?: string;
}

const fixture = JSON.parse(
  readFileSync(new URL("../../../api/fixtures/hostname/v1.json", import.meta.url), "utf8"),
) as Fixture;

describe("hostname conformance", () => {
  it("uses fixture version 1 with unique names", () => {
    expect(fixture.version).toBe(1);
    expect(new Set(fixture.cases.map(({ name }) => name)).size).toBe(fixture.cases.length);
  });

  for (const testCase of fixture.cases) {
    it(testCase.name, () => {
      const canonicalize =
        testCase.context === "hostname" ? canonicalizeHostname : canonicalizeAuthority;
      if (testCase.error) {
        expect(() => canonicalize(testCase.input)).toThrowError(
          expect.objectContaining<Partial<HostnameError>>({ code: testCase.error }),
        );
      } else {
        expect(canonicalize(testCase.input)).toBe(testCase.canonical);
      }
    });
  }
});
