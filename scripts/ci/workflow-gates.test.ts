import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { parse } from "yaml";

function object(value: unknown): Record<string, unknown> {
  assert(value !== null && typeof value === "object" && !Array.isArray(value));
  return value as Record<string, unknown>;
}

it.each([
  ["integration", "integration"],
  ["load", "load"],
])("%s result gate rejects cancelled dependencies", (workflowName, jobName) => {
  const workflow = object(
    parse(
      readFileSync(new URL(`../../.github/workflows/${workflowName}.yml`, import.meta.url), "utf8"),
    ),
  );
  const job = object(object(workflow.jobs)[jobName]);
  expect(job.if).toBe("always()");
  assert(Array.isArray(job.needs) && job.needs.every((name) => typeof name === "string"));
  assert(Array.isArray(job.steps) && job.steps.length === 1);
  const script = object(job.steps[0]).run;
  assert(typeof script === "string");

  for (const extended of [false, true]) {
    const baseline = Object.fromEntries(
      job.needs.map((name: string) => [
        name,
        { result: name === "runtime-extended" && !extended ? "skipped" : "success" },
      ]),
    );
    for (const name of job.needs) {
      const expected = baseline[name];
      assert(expected);
      for (const result of ["success", "failure", "cancelled", "skipped"]) {
        const actual = spawnSync("bash", ["-e", "-o", "pipefail", "-c", script], {
          encoding: "utf8",
          timeout: 5_000,
          env: {
            ...process.env,
            RESULTS: JSON.stringify({ ...baseline, [name]: { result } }),
            EXTENDED_REQUIRED: String(extended),
            GITHUB_STEP_SUMMARY: "/dev/null",
          },
        });
        assert.ifError(actual.error);
        expect(
          actual.status === 0,
          `${name}: ${result}, extended=${extended}\n${actual.stderr}`,
        ).toBe(result === expected.result);
      }
    }
  }
});
