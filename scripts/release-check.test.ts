import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test, vi } from "vitest";

import { publicURLID, readyEvent, visit } from "./release-check.ts";

describe("release check CLI events", () => {
  test("accepts a ready event and rejects incomplete or failed publications", () => {
    expect(readyEvent('{"schema_version":1,"type":"starting"}')).toBeUndefined();
    expect(
      readyEvent(
        '{"schema_version":1,"type":"ready","url":"https://example.com","tunnel_id":"tunnel_1","publish_run_number":2}',
      ),
    ).toEqual({
      url: "https://example.com",
      tunnelID: "tunnel_1",
      publishRunNumber: 2,
    });
    expect(() =>
      readyEvent(
        '{"schema_version":1,"type":"ready","url":"https://example.com","tunnel_id":"tunnel_1","publish_run_number":0}',
      ),
    ).toThrow(/ready/);
    expect(() =>
      readyEvent(
        '{"schema_version":1,"type":"ready","url":"https://example.com","tunnel_id":42,"publish_run_number":2}',
      ),
    ).toThrow(/invalid shape/);
    expect(() =>
      readyEvent('{"schema_version":1,"type":"error","code":"TNL_UNAVAILABLE"}'),
    ).toThrow(/TNL_UNAVAILABLE/);
  });

  test("finds only this tunnel's public URL ID on the selected server", () => {
    const snapshot = {
      tunnels: [
        { tunnel_id: "target", server: "https://control.other.test", public_url_id: "wrong" },
        { tunnel_id: "target", server: "https://control.example.test", public_url_id: "ours" },
      ],
    };
    expect(publicURLID(snapshot, "target", "https://control.example.test")).toBe("ours");
    expect(() => publicURLID(snapshot, "other", "https://control.example.test")).toThrow(
      /no public URL ID/,
    );
    expect(() =>
      publicURLID(
        { tunnels: [{ tunnel_id: "target", server: "https://control.example.test" }] },
        "target",
        "https://control.example.test",
      ),
    ).toThrow(/no public URL ID/);
    expect(() => publicURLID({ tunnels: [{}] }, "target", "https://control.example.test")).toThrow(
      /invalid shape/,
    );
  });
});

test("visits the ready HTTPS hostname and rejects an unrelated local service", async () => {
  const requests: string[] = [];
  vi.stubGlobal("fetch", async (url: URL) => {
    requests.push(url.href);
    return new Response(JSON.stringify({ host: "check.example.com", nonce: "run-1" }), {
      status: 200,
    });
  });
  await visit("https://check.example.com", "run-1");
  expect(requests).toEqual(["https://check.example.com/release-check/run-1"]);
  await expect(visit("https://wrong.example.com", "run-1")).rejects.toThrow(/wrong local service/);
  vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ host: 42, nonce: "run-1" })));
  await expect(visit("https://check.example.com", "run-1")).rejects.toThrow(/invalid shape/);
  await expect(visit("http://check.example.com", "run-1")).rejects.toThrow(/invalid public URL/);
});

test("plan uses explicit inputs without opening client state or contacting a server", () => {
  const root = mkdtempSync(join(tmpdir(), "tnl-release-check-plan-"));
  try {
    const args = [
      "scripts/release-check.ts",
      "plan",
      "--server",
      "https://control.example.test",
      "--team",
      "team_1",
      "--state-dir",
      join(root, "absent-state"),
      "--tnl-binary",
      join(root, "absent-tnl"),
      "--version",
      "0.1.0-rc.36",
    ];
    const output = execFileSync(process.execPath, args, { encoding: "utf8", cwd: process.cwd() });
    expect(JSON.parse(output)).toMatchObject({
      server: "https://control.example.test",
      read_only: true,
      checks: ["generated ephemeral URL", "saved URL republish"],
    });
    expect(readdirSync(root)).toEqual([]);
    expect(() =>
      execFileSync(
        process.execPath,
        args.map((value) =>
          value === "https://control.example.test" ? "http://control.example.test" : value,
        ),
        { cwd: process.cwd(), stdio: "ignore" },
      ),
    ).toThrow();
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
