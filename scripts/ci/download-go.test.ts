import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { downloadModules, retryableDownload } from "./download-go.ts";

describe("dependency acquisition", () => {
  it.each([
    "reading https://proxy.golang.org/module.zip: 503 Service Unavailable",
    "stream error: stream ID 9; INTERNAL_ERROR; received from peer",
    "HTTP status server error (504 Gateway Timeout) for url (https://example.com/tool)",
    "read: connection reset by peer",
    "dial tcp: i/o timeout",
  ])("recognizes transient download failure: %s", (output) => {
    expect(retryableDownload(output)).toBe(true);
  });

  it.each([
    "unknown revision v1.0.0",
    "checksum mismatch",
    "compile error",
    "404 Not Found",
    "410 Gone",
    "503 Service Unavailable\n410 Gone",
    "504 Gateway Timeout\nSECURITY ERROR: checksum mismatch",
    "503 Service Unavailable\nx509: certificate signed by unknown authority",
    "504 Gateway Timeout\n403 Forbidden",
  ])("does not retry permanent or mixed failures: %s", (output) => {
    expect(retryableDownload(output)).toBe(false);
  });

  const failed = { status: 1, output: "503 Service Unavailable", interrupted: false };
  const passed = { status: 0, output: "", interrupted: false };

  it("retries acquisition at most three times, with bounded waits", async () => {
    const execute = vi.fn(() => failed);
    const wait = vi.fn(async () => {});
    const summarize = vi.fn();
    expect(await downloadModules(".", execute, wait, summarize)).toBe(1);
    expect(execute).toHaveBeenCalledTimes(3);
    expect(wait.mock.calls).toEqual([[5_000], [10_000]]);
    expect(summarize).toHaveBeenCalledWith(expect.stringContaining("failed on attempt 3/3"));
  });

  it("stops after a successful retry and reports the recovery", async () => {
    const execute = vi.fn().mockReturnValueOnce(failed).mockReturnValueOnce(passed);
    const wait = vi.fn(async () => {});
    const summarize = vi.fn();
    expect(await downloadModules("tools/testharness", execute, wait, summarize)).toBe(0);
    expect(execute).toHaveBeenCalledTimes(2);
    expect(execute).toHaveBeenCalledWith("tools/testharness");
    expect(summarize).toHaveBeenCalledWith(expect.stringContaining("downloaded on attempt 2/3"));
  });

  it.each([
    { status: 2, output: "checksum mismatch", interrupted: false },
    { status: null, output: "503 Service Unavailable", interrupted: true },
    { status: 0, output: "503 Service Unavailable", interrupted: true },
  ])("does not retry errors or cancellation: %j", async (result) => {
    const execute = vi.fn(() => result);
    const wait = vi.fn(async () => {});
    expect(await downloadModules(".", execute, wait, () => {})).toBe(result.status || 1);
    expect(execute).toHaveBeenCalledTimes(1);
    expect(wait).not.toHaveBeenCalled();
  });

  it.each([false, true])(
    "downloads and verifies both modules; verification failure=%s",
    (failVerify) => {
      const directory = realpathSync(mkdtempSync(join(tmpdir(), "tnl-ci-download-")));
      try {
        mkdirSync(join(directory, "tools/testharness"), { recursive: true });
        const go = join(directory, "go");
        const log = join(directory, "calls.log");
        writeFileSync(
          go,
          `#!/bin/sh\nprintf '%s:%s\\n' "$PWD" "$*" >> "$CALLS"\nif [ "$*" = 'mod verify' ]; then exit "$VERIFY_STATUS"; fi\n`,
        );
        chmodSync(go, 0o755);
        const result = spawnSync(
          process.execPath,
          [fileURLToPath(new URL("download-go.ts", import.meta.url))],
          {
            cwd: directory,
            encoding: "utf8",
            env: {
              ...process.env,
              PATH: `${directory}:${process.env.PATH}`,
              CALLS: log,
              VERIFY_STATUS: failVerify ? "2" : "0",
              GITHUB_STEP_SUMMARY: "",
            },
          },
        );
        expect(result.status, result.stderr).toBe(failVerify ? 2 : 0);
        const calls = readFileSync(log, "utf8").trim().split("\n");
        expect(calls).toEqual([
          `${directory}:mod download`,
          `${directory}:mod verify`,
          ...(!failVerify
            ? [
                `${directory}/tools/testharness:mod download`,
                `${directory}/tools/testharness:mod verify`,
              ]
            : []),
        ]);
      } finally {
        rmSync(directory, { recursive: true, force: true });
      }
    },
  );
});
