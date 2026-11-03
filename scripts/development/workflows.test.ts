import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { z } from "zod";

const workflow = z.object({
  jobs: z.record(
    z.string(),
    z.object({
      "runs-on": z.unknown(),
      steps: z.array(
        z.object({
          uses: z.string().optional(),
          with: z.record(z.string(), z.unknown()).optional(),
        }),
      ),
    }),
  ),
});

describe("CI toolchain compatibility", () => {
  it("keeps every pinned Python consumer on a supported runner", () => {
    const python = /^python = "([^"]+)"$/m.exec(readFileSync("mise.toml", "utf8"))?.[1];
    expect(python).toBeDefined();
    let consumers = 0;
    for (const file of readdirSync(".github/workflows")) {
      if (!file.endsWith(".yml")) continue;
      const data = workflow.parse(parse(readFileSync(join(".github/workflows", file), "utf8")));
      for (const [name, job] of Object.entries(data.jobs)) {
        for (const step of job.steps) {
          if (!step.uses?.startsWith("actions/setup-python@")) continue;
          consumers++;
          // setup-python's 3.13.9 manifest has no ubuntu 26.04 interpreter.
          // changing this pairing requires checking the new download manifest.
          expect(job["runs-on"], `${file}: ${name}`).toBe("ubuntu-24.04");
          expect(step.with?.["python-version"], `${file}: ${name}`).toBe(python);
        }
      }
    }
    expect(consumers).toBeGreaterThan(0);
  });
});
