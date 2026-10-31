import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import {
  fixtureReportPrefix,
  fixtureStep,
  formatChildFailure,
  formatFixtureFailure,
  InstalledDrizzleFailure,
  observeDrizzleConfig,
  readChildFailure,
  type FixtureStage,
} from "../fixtures/connections/installed-drizzle-diagnostics.ts";

const secret = "synthetic-secret https://user:password@example.test PRIVATE KEY /private/handle";
const childPrefix = "tnl-drizzle-child ";
const run = promisify(execFile);

function report(cause: unknown): Record<string, unknown> {
  const rendered = formatFixtureFailure(cause);
  expect(rendered).not.toContain(secret);
  assert(rendered.startsWith(fixtureReportPrefix));
  const value: unknown = JSON.parse(rendered.slice(fixtureReportPrefix.length));
  assert(typeof value === "object" && value !== null);
  return value as Record<string, unknown>;
}

describe("installed Drizzle fixture diagnostics", () => {
  it.each<FixtureStage>([
    "filesystem preparation",
    "installed settings verifier",
    "drizzle migration",
    "post-migration query",
  ])("preserves the actual injected cause and distinct %s boundary", async (stage) => {
    const cause = Object.assign(new Error(secret), { code: "sdk.response_invalid" });
    const failure = await fixtureStep(stage, () => {
      throw cause;
    }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(InstalledDrizzleFailure);
    assert(failure instanceof InstalledDrizzleFailure);
    expect(failure.cause).toBe(cause);
    expect(report(failure)).toMatchObject({
      code: "fixture.installed_drizzle_failed",
      stage,
      cause_status: "reported",
      error_code: "sdk.response_invalid",
    });
    expect(report(failure).elapsed_ms).toEqual(expect.any(Number));
    expect(cause.message).toBe(secret);
  });

  it("never renders messages, stacks, output, args, env, nested causes, or unknown fields", () => {
    const nested = Object.assign(new Error(secret), { code: "42P01" });
    const cause = Object.assign(new Error(secret, { cause: nested }), {
      stack: secret,
      stdout: secret,
      stderr: secret,
      args: [secret],
      env: { PASSWORD: secret },
      future: secret,
      code: "ERR_ASSERTION",
    });
    const failure = new InstalledDrizzleFailure("installed settings verifier", 12, cause);
    expect(failure.cause).toBe(cause);
    expect(cause.cause).toBe(nested);
    expect(report(failure)).toEqual({
      code: "fixture.installed_drizzle_failed",
      stage: "installed settings verifier",
      elapsed_ms: 12,
      cause_status: "truncated",
      error_code: "ERR_ASSERTION",
    });
  });

  it("uses data fields, never human text or a code-shaped guess", () => {
    for (const code of [undefined, "sdk.future_code", "42BAD", secret, 1.5, -1, 256, null]) {
      expect(
        report(
          new InstalledDrizzleFailure("drizzle migration", 0, {
            code,
            message: "sdk.response_invalid ERR_ASSERTION 42P01",
            stack: "ETIMEDOUT SIGTERM",
            stdout: formatChildFailure({ code: "sdk.response_invalid" }),
          }),
        ),
      ).toMatchObject({ cause_status: "unknown" });
    }
    for (const code of ["sdk.connection_unavailable", "ERR_ASSERTION", "42P01"]) {
      expect(report(new InstalledDrizzleFailure("drizzle migration", 0, { code }))).toMatchObject({
        cause_status: "reported",
        error_code: code,
      });
    }
  });

  it("does not invoke accessors or trust a forged owned error", () => {
    let calls = 0;
    const cause: object = {};
    for (const key of [
      "code",
      "errno",
      "signal",
      "killed",
      "stderr",
      "message",
      "stack",
      "args",
      "env",
      "future",
    ]) {
      Object.defineProperty(cause, key, {
        get() {
          calls++;
          throw new Error(secret);
        },
      });
    }
    expect(report(new InstalledDrizzleFailure("drizzle migration", null, cause))).toMatchObject({
      cause_status: "unknown",
      elapsed_ms: null,
    });
    Object.defineProperty(cause, "cause", {
      get() {
        calls++;
        throw new Error(secret);
      },
    });
    expect(report(new InstalledDrizzleFailure("drizzle migration", 0, cause))).toMatchObject({
      cause_status: "truncated",
    });
    expect(calls).toBe(0);
    expect(report(Object.create(InstalledDrizzleFailure.prototype))).toMatchObject({
      stage: "fixture preparation",
      cause_status: "unknown",
    });
    const hostile = new Proxy(
      {},
      {
        getOwnPropertyDescriptor() {
          throw new Error(secret);
        },
        getPrototypeOf() {
          throw new Error(secret);
        },
      },
    );
    expect(report(hostile)).toMatchObject({ cause_status: "unknown" });
  });

  it("keeps the execFile status separate from an approved child machine cause", () => {
    const cause = Object.assign(new Error(secret), {
      code: 1,
      errno: -2,
      signal: "SIGTERM",
      killed: true,
      stderr:
        secret +
        "\n" +
        formatChildFailure({ code: "42P01", signal: "SIGKILL", killed: false, errno: -1 }),
    });
    expect(report(new InstalledDrizzleFailure("post-migration query", 3, cause))).toEqual({
      code: "fixture.installed_drizzle_failed",
      stage: "post-migration query",
      elapsed_ms: 3,
      cause_status: "reported",
      error_code: "42P01",
      exit_code: 1,
      errno: -2,
      signal: "SIGTERM",
      killed: true,
    });
  });

  it.each([
    "{",
    "[]",
    "null",
    '{"code":"fixture.drizzle_child_failed","cause_status":"reported"}',
    '{"code":"fixture.drizzle_child_failed","cause_status":"unknown","code":"fixture.drizzle_child_failed"}',
    '{"code":"fixture.drizzle_child_failed","cause_status":"unknown","future":"secret"}',
    '{"code":"fixture.drizzle_child_failed","cause_status":"unknown","error_code":"sdk.future"}',
    '{"code":"fixture.drizzle_child_failed","cause_status":"unknown","exit_code":1.5}',
    '{"code":"fixture.drizzle_child_failed","cause_status":"unknown","errno":1}',
    '{"code":"fixture.drizzle_child_failed","cause_status":"unknown","signal":"future"}',
    '{"code":"fixture.drizzle_child_failed","cause_status":"unknown","killed":"true"}',
    '{"code":"fixture.drizzle_child_failed","cause_status":"unknown","cause":{"code":"42P01"}}',
    '{"code":"fixture.drizzle_child_failed","cause_status":"unknown","cause":' +
      "[".repeat(200) +
      "0" +
      "]".repeat(200) +
      "}",
    '{"code":"fixture.drizzle_child_failed","cause_status":"unknown","a":1,"b":2,"c":3,"d":4,"e":5,"f":6}',
  ])("rejects malformed or non-flat child record %#", (text) => {
    expect(readChildFailure(childPrefix + text)).toEqual({ cause_status: "unknown" });
  });

  it("makes byte, record, line, and nested-cause truncation explicit", () => {
    const valid = formatChildFailure({ code: "sdk.response_invalid" });
    expect(readChildFailure(valid + secret.repeat(200))).toMatchObject({
      cause_status: "truncated",
    });
    expect(
      readChildFailure(
        childPrefix +
          JSON.stringify({
            code: "fixture.drizzle_child_failed",
            cause_status: "unknown",
            extra: secret.repeat(30),
          }),
      ),
    ).toEqual({ cause_status: "truncated" });
    expect(readChildFailure(valid + "\n".repeat(40))).toMatchObject({ cause_status: "truncated" });
    expect(readChildFailure(valid + valid)).toEqual({ cause_status: "truncated" });
    expect(
      readChildFailure(formatChildFailure(new Error(secret, { cause: { code: "42P01" } }))),
    ).toEqual({ cause_status: "truncated" });
    expect(
      readChildFailure({
        toString() {
          throw new Error(secret);
        },
      }),
    ).toBeUndefined();
  });

  it("does not change successful stage/config values", async () => {
    const value = Object.freeze({ ordinary: true });
    expect(observeDrizzleConfig(() => value)).toBe(value);
    expect(await fixtureStep("installed settings verifier", () => value)).toBe(value);
  });

  it("retains the original and cleanup causes while rendering only their safe reports", () => {
    const cause = Object.assign(new Error(secret), { code: "sdk.response_invalid" });
    const cleanupCause = Object.assign(new Error(secret), { code: "EACCES", errno: -13 });
    const failure = new InstalledDrizzleFailure("drizzle migration", 7, cause);
    const cleanup = new InstalledDrizzleFailure("consumer cleanup", 1, cleanupCause);
    expect(failure.withCleanup(cleanup)).toBe(failure);
    expect(failure.cause).toBe(cause);
    expect(failure.cleanup).toBe(cleanup);
    expect(failure.cleanup?.cause).toBe(cleanupCause);
    const rendered = formatFixtureFailure(failure);
    expect(rendered).toBe(
      formatFixtureFailure(new InstalledDrizzleFailure("drizzle migration", 7, cause)) +
        formatFixtureFailure(cleanup),
    );
    expect(rendered).not.toContain(secret);
  });

  it.each([
    { verificationFails: true, cleanupFails: true },
    { verificationFails: true, cleanupFails: false },
    { verificationFails: false, cleanupFails: true },
    { verificationFails: false, cleanupFails: false },
  ])(
    "runs installed fixture cleanup without replacing the original failure: %j",
    async ({ verificationFails, cleanupFails }) => {
      const fixture = new URL("../fixtures/connections/installed-drizzle.ts", import.meta.url).href;
      // run the actual entry point with failed file operations, without installing
      // packages or needing a native owner. both errors contain private text.
      let stdout = "";
      let stderr = "";
      let exitCode: unknown = 0;
      try {
        ({ stdout, stderr } = await run(
          process.execPath,
          [
            "--input-type=module",
            "-e",
            `
        import assert from "node:assert/strict";
        import fs from "node:fs/promises";
        import childProcess from "node:child_process";
        import {syncBuiltinESMExports} from "node:module";
        const cause = Object.assign(new Error(${JSON.stringify(secret)}), {code: "sdk.response_invalid"});
        const cleanupCause = Object.assign(new Error(${JSON.stringify(secret)}), {code: "EACCES", errno: -13});
        fs.mkdtemp = async () => "/synthetic-installed-drizzle";
        for (const key of ["mkdir", "chmod", "cp", "writeFile"]) fs[key] = async () => {};
        fs.copyFile = async () => { if (${verificationFails}) throw cause; };
        let cleaned = 0;
        fs.rm = async () => { cleaned++; if (${cleanupFails}) throw cleanupCause; };
        childProcess.execFile = (...args) => { args.at(-1)(null, "", ""); };
        syncBuiltinESMExports();
        process.argv = [process.execPath, "installed-drizzle.ts", "/synthetic-tnl", "http"];
        process.env.TNL_CONNECTION_HANDLE = "synthetic-handle";
        await import(${JSON.stringify(fixture)});
        assert.equal(cleaned, 1);
        `,
          ],
          { timeout: 10_000 },
        ));
      } catch (cause) {
        assert(typeof cause === "object" && cause !== null);
        assert("stdout" in cause && typeof cause.stdout === "string");
        assert("stderr" in cause && typeof cause.stderr === "string");
        assert("code" in cause);
        stdout = cause.stdout;
        stderr = cause.stderr;
        exitCode = cause.code;
      }
      expect(exitCode).toBe(verificationFails || cleanupFails ? 1 : 0);
      expect(stdout).toBe(
        verificationFails || cleanupFails ? "" : "installed package connection checks passed\n",
      );
      expect(stderr).not.toContain(secret);
      const reports = stderr
        .trimEnd()
        .split("\n")
        .filter(Boolean)
        .map((line): unknown => {
          expect(line.startsWith(fixtureReportPrefix)).toBe(true);
          return JSON.parse(line.slice(fixtureReportPrefix.length));
        });
      expect(reports).toEqual([
        ...(verificationFails
          ? [
              {
                code: "fixture.installed_drizzle_failed",
                stage: "fixture preparation",
                elapsed_ms: expect.any(Number),
                cause_status: "reported",
                error_code: "sdk.response_invalid",
              },
            ]
          : []),
        ...(cleanupFails
          ? [
              {
                code: "fixture.installed_drizzle_failed",
                stage: "consumer cleanup",
                elapsed_ms: expect.any(Number),
                cause_status: "unknown",
                errno: -13,
              },
            ]
          : []),
      ]);
    },
  );

  it("preserves an actual failed Node child without rendering its private output or args", async () => {
    const helper = new URL(
      "../fixtures/connections/installed-drizzle-diagnostics.ts",
      import.meta.url,
    ).href;
    let childCause: unknown;
    const failure = await fixtureStep("drizzle migration", async () => {
      try {
        await run(process.execPath, [
          "--input-type=module",
          "-e",
          `
      import assert from "node:assert/strict";
      import {observeDrizzleConfig} from ${JSON.stringify(helper)};
      const cause = Object.assign(new Error(${JSON.stringify(secret)}), {code: "sdk.response_invalid", stdout: ${JSON.stringify(secret)}, env: {PASSWORD: ${JSON.stringify(secret)}}});
      try {
        observeDrizzleConfig(() => { throw cause; });
        assert.fail("injection did not fail");
      } catch (observed) {
        assert.equal(observed, cause);
        throw observed;
      }
    `,
        ]);
      } catch (cause) {
        childCause = cause;
        throw cause;
      }
    }).catch((cause: unknown) => cause);
    assert(failure instanceof InstalledDrizzleFailure);
    expect(failure.cause).toBe(childCause);
    assert(typeof childCause === "object" && childCause !== null && "stderr" in childCause);
    expect(typeof childCause.stderr === "string" && childCause.stderr.includes(secret)).toBe(true);
    expect(report(failure)).toMatchObject({
      stage: "drizzle migration",
      cause_status: "reported",
      error_code: "sdk.response_invalid",
      exit_code: 1,
    });
  });
});
