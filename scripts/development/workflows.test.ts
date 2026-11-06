import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { z } from "zod";

const step = z.object({
  name: z.string().optional(),
  uses: z.string().optional(),
  run: z.string().optional(),
  if: z.string().optional(),
  "timeout-minutes": z.number().optional(),
  with: z.record(z.string(), z.unknown()).optional(),
  env: z.record(z.string(), z.unknown()).optional(),
});
const workflow = z.object({
  on: z.record(z.string(), z.unknown()),
  jobs: z.record(
    z.string(),
    z.object({
      "runs-on": z.unknown(),
      if: z.string().optional(),
      needs: z.union([z.string(), z.array(z.string())]).optional(),
      permissions: z.record(z.string(), z.string()).optional(),
      strategy: z
        .object({
          "fail-fast": z.boolean().optional(),
          matrix: z.record(z.string(), z.unknown()),
        })
        .optional(),
      steps: z.array(step),
    }),
  ),
});
const action = z.object({
  inputs: z.record(z.string(), z.object({ default: z.string().optional() })),
  runs: z.object({ steps: z.array(step) }),
});

function readWorkflow(file: string) {
  return workflow.parse(parse(readFileSync(join(".github/workflows", file), "utf8")));
}

function gateStatus(run: string | undefined, env: Record<string, string>) {
  const result = spawnSync("bash", ["-e", "-c", z.string().parse(run)], {
    env: { PATH: process.env.PATH, NODE_ENV: "test", ...env },
    encoding: "utf8",
  });
  expect(result.error).toBeUndefined();
  return result.status;
}

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

describe("CI scheduling and required checks", () => {
  it("runs each unchanged smoke workload independently and retains separate evidence", () => {
    const { runtime } = readWorkflow("load.yml").jobs;
    assert(runtime);
    expect(runtime.strategy).toEqual({
      "fail-fast": false,
      matrix: { scenario: ["smoke", "relay-kill", "connect"] },
    });
    expect(runtime.needs).toBeUndefined();
    expect(runtime.steps.filter((item) => item.run?.startsWith("task go:test:load:"))).toEqual([
      {
        name: "Run runtime smoke",
        if: "matrix.scenario == 'smoke'",
        run: "task go:test:load:runtime RACE=1 RESULTS=bench-results/ci-smoke",
      },
      {
        name: "Run relay-kill fallback workload",
        if: "matrix.scenario == 'relay-kill'",
        run: "task go:test:load:runtime SCENARIO=relay-kill RPS=160 RESULTS=bench-results/ci-relay-kill",
      },
      {
        name: "Run connector load smoke",
        if: "matrix.scenario == 'connect'",
        run: "task go:test:load:connect RACE=1 RESULTS=bench-results/ci-connect",
      },
    ]);
    const evidence = runtime.steps.find((item) =>
      item.uses?.startsWith("actions/upload-artifact@"),
    );
    expect(evidence?.if).toBe("always()");
    expect(evidence?.with).toMatchObject({
      name: "runtime-workloads-${{ matrix.scenario }}",
      path: "bench-results/ci-*",
      "retention-days": 7,
    });
  });

  it("keeps every extended workload on schedules and manual runs", () => {
    const extended = readWorkflow("load.yml").jobs["runtime-extended"];
    assert(extended);
    expect(extended.if).toBe(
      "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'",
    );
    expect(extended.needs).toBeUndefined();
    expect(
      extended.steps
        .find((item) => item.run?.startsWith("task go:test:load:"))
        ?.run?.trim()
        .split("\n"),
    ).toEqual([
      "task go:test:load:runtime PUBLIC_URLS=64 START_PARALLEL=64 RPS=160 DURATION=30s RESULTS=bench-results/ci-reference",
      "task go:test:load:runtime SCENARIO=forwarding-blackhole RESULTS=bench-results/ci-forwarding-blackhole",
      "task go:test:load:runtime SCENARIO=publisher-blackhole RESULTS=bench-results/ci-publisher-blackhole",
      "task go:test:load:runtime SCENARIO=udp-fallback RESULTS=bench-results/ci-udp-fallback",
      "task go:test:load:connect SCENARIO=latency NETWORK_PATH=publisher RTT=50ms RESULTS=bench-results/ci-connect-publisher-latency",
      "task go:test:load:connect SCENARIO=latency NETWORK_PATH=connector RTT=50ms RESULTS=bench-results/ci-connect-connector-latency",
    ]);
  });

  it("keeps the required Python result dependent on SDK and installed-package checks", () => {
    const jobs = readWorkflow("checks.yml").jobs;
    assert(jobs["python-sdk"] && jobs.packages && jobs.python);
    expect(jobs["python-sdk"].needs).toBeUndefined();
    expect(jobs.packages.needs).toBeUndefined();
    expect(jobs["python-sdk"].steps.some((item) => item.run === "task py:check")).toBe(true);
    expect(
      jobs.packages.steps.find((item) => item.run?.startsWith("task release:snapshot"))?.run,
    ).toBe("task release:snapshot\ntask release:npm-package\ntask py:build\n");
    expect(
      jobs.packages.steps.some((item) => item.run === "python3 -m pip install uv==0.9.18"),
    ).toBe(true);
    expect(jobs.python).toMatchObject({
      if: "always()",
      needs: ["python-sdk", "packages"],
      permissions: {},
    });
    const gate = jobs.python.steps[0];
    assert(gate);
    expect(gate.env).toEqual({
      PYTHON_RESULT: "${{ needs.python-sdk.result }}",
      PACKAGES_RESULT: "${{ needs.packages.result }}",
    });
    expect(gateStatus(gate.run, { PYTHON_RESULT: "success", PACKAGES_RESULT: "success" })).toBe(0);
    for (const result of ["failure", "cancelled", "skipped"]) {
      expect(gateStatus(gate.run, { PYTHON_RESULT: result, PACKAGES_RESULT: "success" })).not.toBe(
        0,
      );
      expect(gateStatus(gate.run, { PYTHON_RESULT: "success", PACKAGES_RESULT: result })).not.toBe(
        0,
      );
    }
  });

  it("fails the load gate for any required workload that did not pass", () => {
    const { load } = readWorkflow("load.yml").jobs;
    assert(load);
    expect(load).toMatchObject({
      if: "always()",
      needs: ["database", "runtime", "runtime-extended"],
      permissions: {},
    });
    const gate = load.steps[0];
    assert(gate);
    expect(gate.env).toEqual({
      DATABASE_RESULT: "${{ needs.database.result }}",
      RUNTIME_RESULT: "${{ needs.runtime.result }}",
      EXTENDED_RESULT: "${{ needs.runtime-extended.result }}",
      EXTENDED_REQUIRED:
        "${{ github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' }}",
    });
    for (const required of ["true", "false"]) {
      const success = {
        DATABASE_RESULT: "success",
        RUNTIME_RESULT: "success",
        EXTENDED_RESULT: required === "true" ? "success" : "skipped",
        EXTENDED_REQUIRED: required,
      };
      expect(gateStatus(gate.run, success)).toBe(0);
      for (const result of ["failure", "cancelled", "skipped"]) {
        for (const key of ["DATABASE_RESULT", "RUNTIME_RESULT"]) {
          expect(gateStatus(gate.run, { ...success, [key]: result })).not.toBe(0);
        }
        expect(
          gateStatus(gate.run, { ...success, EXTENDED_REQUIRED: "true", EXTENDED_RESULT: result }),
        ).not.toBe(0);
      }
    }
  });

  it("bounds APT downloads without bypassing package verification", () => {
    const apt = readWorkflow("integration.yml").jobs.clients?.steps.find(
      (item) => item.name === "Install OpenSSH fixture",
    );
    expect(apt?.["timeout-minutes"]).toBe(3);
    expect(apt?.run).toContain("https://archive.ubuntu.com/ubuntu/");
    expect(apt?.run).toContain("https://security.ubuntu.com/ubuntu/");
    expect(apt?.run).toContain("Acquire::Retries=2");
    expect(apt?.run).toContain("Acquire::https::Timeout=15");
    expect(apt?.run).toContain("APT::Update::Error-Mode=any");
    expect(apt?.run).not.toMatch(/allow-unauthenticated|trusted=yes|Verify-Peer=false/);
    assert(apt?.run);
    const expressions = [...apt.run.matchAll(/-e '([^']+)'/g)].flatMap((match) => [
      "-e",
      z.string().parse(match[1]),
    ]);
    const rewritten = spawnSync("sed", ["-E", ...expressions], {
      encoding: "utf8",
      input: [
        "URIs: mirror+file:/etc/apt/apt-mirrors.txt",
        "URIs: http://azure.archive.ubuntu.com/ubuntu/",
        "URIs: http://archive.ubuntu.com/ubuntu",
        "URIs: http://security.ubuntu.com/ubuntu/",
        "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg",
      ].join("\n"),
    });
    expect(rewritten.status).toBe(0);
    expect(rewritten.stdout).toBe(
      [
        ...Array<string>(3).fill("URIs: https://archive.ubuntu.com/ubuntu/"),
        "URIs: https://security.ubuntu.com/ubuntu/",
        "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg",
      ].join("\n"),
    );
  });
});

describe("CI cache boundaries", () => {
  it("disables implicit cache writes and gates explicit writes on main pushes", () => {
    for (const name of ["setup-go", "setup-pnpm"]) {
      const data = action.parse(parse(readFileSync(`.github/actions/${name}/action.yml`, "utf8")));
      expect(data.inputs["cache-save"]?.default).toBe("false");
      const writers = data.runs.steps.filter((item) =>
        item.uses?.match(/^actions\/cache(@|\/save@)/),
      );
      expect(writers).toHaveLength(1);
      expect(writers[0]?.if).toContain("inputs.cache-save == 'true'");
      expect(writers[0]?.if).toContain(
        "github.event_name == 'push' && github.ref == 'refs/heads/main'",
      );
      for (const item of data.runs.steps) {
        if (item.uses?.match(/^(actions\/setup-go|pnpm\/action-setup)@/))
          expect(item.with?.cache).toBe(false);
        if (item.uses?.startsWith("actions/setup-node@"))
          expect(item.with?.["package-manager-cache"]).toBe(false);
      }
      const restore = data.runs.steps.find((item) =>
        item.uses?.startsWith("actions/cache/restore@"),
      );
      expect(restore).toBeDefined();
      expect(restore?.with?.key).toContain("${{ runner.os }}-${{ runner.arch }}");
      if (name === "setup-go") {
        expect(restore?.if).toBe(
          "inputs.cache-save != 'true' || github.event_name != 'push' || github.ref != 'refs/heads/main'",
        );
        expect(restore?.with?.key).toContain("${{ inputs.cache-scope }}");
        expect(restore?.with?.key).toContain("${{ github.sha }}");
        expect(restore?.with?.["restore-keys"]).not.toContain("${{ github.sha }}");
      }
    }
  });

  it("keeps credential-bearing jobs outside the shared Go and pnpm caches", () => {
    for (const file of readdirSync(".github/workflows").filter((name) => name.endsWith(".yml"))) {
      const data = readWorkflow(file);
      expect(data.on).not.toHaveProperty("pull_request_target");
      for (const [name, job] of Object.entries(data.jobs)) {
        for (const item of job.steps) {
          if (item.uses?.startsWith("actions/setup-go@"))
            expect(item.with?.cache, `${file}: ${name}`).toBe(false);
          if (item.uses?.match(/^\.\/\.github\/actions\/setup-(go|pnpm)$/)) {
            expect(file).not.toBe("release.yml");
            expect(Object.values(job.permissions ?? {}), `${file}: ${name}`).not.toContain("write");
          }
        }
        if (job.steps.some((item) => item.uses === "./.github/actions/setup-pnpm")) {
          expect(
            job.steps.some((item) => item.run?.includes("pnpm install")),
            `${file}: ${name}`,
          ).toBe(false);
        }
      }
    }
  });

  it("does not export Docker caches or extract unused cache mounts on PRs", () => {
    const steps = readWorkflow("checks.yml").jobs.container?.steps;
    assert(steps);
    const writer = steps.find((item) => item.uses?.startsWith("actions/cache@"));
    expect(writer?.if).toBe("github.event_name == 'push' && github.ref == 'refs/heads/main'");
    const build = steps.find((item) => item.name === "Build multi-platform image");
    expect(build?.with?.["cache-to"]).toBe(
      "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' && 'type=gha,mode=max,scope=tnl-container-check' || '' }}",
    );
    const dance = steps.find((item) =>
      item.uses?.startsWith("reproducible-containers/buildkit-cache-dance@"),
    );
    expect(dance?.with?.["skip-extraction"]).toBe(
      "${{ github.event_name != 'push' || github.ref != 'refs/heads/main' }}",
    );
  });
});
