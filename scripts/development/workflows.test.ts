import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
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

  it("uses the shared Go dependency setup in every Go workflow", () => {
    let consumers = 0;
    for (const file of readdirSync(".github/workflows")) {
      if (!file.endsWith(".yml")) continue;
      const data = workflow.parse(parse(readFileSync(join(".github/workflows", file), "utf8")));
      for (const job of Object.values(data.jobs)) {
        for (const step of job.steps) {
          expect(step.uses?.startsWith("actions/setup-go@"), file).not.toBe(true);
          if (step.uses === "./.github/actions/setup-go") consumers++;
        }
      }
    }
    expect(consumers).toBe(18);
  });

  for (const failures of [0, 2, 3]) {
    it(`bounds dependency retries after ${failures} download failures`, () => {
      const action = z
        .object({ runs: z.object({ steps: z.array(z.object({ run: z.string().optional() })) }) })
        .parse(parse(readFileSync(".github/actions/setup-go/action.yml", "utf8")));
      const script = action.runs.steps.find((step) => step.run)?.run;
      if (!script) throw new Error("dependency setup has no download step");
      const root = mkdtempSync(join(tmpdir(), "tnl-go-setup-"));
      try {
        const calls = join(root, "calls");
        writeFileSync(
          join(root, "go"),
          `#!/bin/bash
echo "$*" >> "$CALLS"
count=$(wc -l < "$CALLS")
if [ "$count" -le "$FAILURES" ]; then exit 1; fi
`,
          { mode: 0o700 },
        );
        writeFileSync(join(root, "sleep"), "#!/bin/bash\nexit 0\n", { mode: 0o700 });
        const result = spawnSync("bash", ["-e", "-o", "pipefail", "-c", script], {
          env: {
            ...process.env,
            PATH: `${root}:${process.env.PATH}`,
            CALLS: calls,
            FAILURES: String(failures),
          },
          encoding: "utf8",
          timeout: 5_000,
        });
        expect(result.error).toBeUndefined();
        expect(result.status, result.stderr).toBe(failures === 3 ? 1 : 0);
        const attempts = readFileSync(calls, "utf8").trim().split("\n");
        expect(attempts).toEqual([
          ...Array.from({ length: failures === 3 ? 3 : failures + 1 }, () => "-C . mod download"),
          ...(failures === 3
            ? []
            : ["-C tools/testharness mod download", "-C tools/staticcheck mod download"]),
        ]);
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    });
  }
});
