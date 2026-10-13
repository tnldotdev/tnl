import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

test("deployment rejects an unpinned image without exposing the database URL", () => {
  const result = spawnSync(
    process.execPath,
    [
      fileURLToPath(new URL("./deploy-server.ts", import.meta.url)),
      "production",
      "ghcr.io/tnldotdev/tnl:latest",
      "0.1.0-rc.41",
      "a".repeat(40),
    ],
    {
      encoding: "utf8",
      env: { ...process.env, TNLD_DATABASE_DIRECT_URL: "private-test-secret" },
    },
  );
  expect(result.status).toBe(1);
  expect(result.stderr).toBe("server deployment: invalid image digest\n");
  expect(result.stdout).toBe("");
});

test("staging rejects a production Environment branch before starting Fly", () => {
  const commit = "a".repeat(40);
  const result = spawnSync(
    process.execPath,
    [
      fileURLToPath(new URL("./deploy-server.ts", import.meta.url)),
      "staging",
      `ghcr.io/tnldotdev/tnl@sha256:${"b".repeat(64)}`,
      `main-${commit}`,
      commit,
    ],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        TNLD_DATABASE_BRANCH: "production",
        TNLD_DATABASE_DIRECT_URL: "postgres://migrator:private-test-secret@db.pg.psdb.cloud/tnl",
      },
    },
  );
  expect(result.status).toBe(1);
  expect(result.stderr).toBe("server deployment: database branch does not match staging\n");
  expect(result.stdout).toBe("");
});
