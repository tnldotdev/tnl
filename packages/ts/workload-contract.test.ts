import { expect, test } from "vitest";
import { sessionSchema } from "./src/internal/workload_contract.js";

function session(provider: string): Record<string, unknown> {
  const id = `wls_${"s".repeat(22)}`;
  return {
    id,
    credential: `wlc_${"x".repeat(43)}`,
    team_id: `tm_${"t".repeat(22)}`,
    project_key: "store",
    workload: "storefront",
    provider,
    subject: { kind: "workload_session", workload_session_id: id },
    lease_expires_at: "2026-10-21T00:01:30Z",
    expires_at: "2026-10-21T01:00:00Z",
    renew_after: "2026-10-21T00:00:30Z",
    service_ids: [`psvc_${"p".repeat(22)}`],
    binding: "b".repeat(64),
    ...(provider === "github"
      ? {
          github: {
            repository_id: "12345",
            repository_owner_id: "6789",
            run_id: "111",
            run_attempt: "1",
            check_run_id: "222",
          },
        }
      : {}),
  };
}

test.each(["github", "vercel", "fly", "oidc"])("session metadata is exact for %s", (provider) => {
  const raw = session(provider);
  expect(sessionSchema.parse(raw)).toEqual(raw);
  if (provider !== "github") {
    for (const github of [{}, null, session("github").github]) {
      expect(sessionSchema.safeParse({ ...raw, github }).success).toBe(false);
    }
  }
  for (const field of ["run_id", "run_attempt", "check_run_id", "unknown"]) {
    expect(sessionSchema.safeParse({ ...raw, [field]: "" }).success).toBe(false);
  }
});

test("GitHub sessions require every signed immutable execution ID", () => {
  const raw = session("github");
  delete raw.github;
  expect(sessionSchema.safeParse(raw).success).toBe(false);
  const github = {
    repository_id: "12345",
    repository_owner_id: "6789",
    run_id: "111",
    run_attempt: "1",
    check_run_id: "222",
  };
  for (const field of Object.keys(github)) {
    for (const value of [undefined, null, "", "0", "job-name", "1".repeat(21), 123]) {
      expect(
        sessionSchema.safeParse({ ...raw, github: { ...github, [field]: value } }).success,
      ).toBe(false);
    }
  }
  expect(sessionSchema.safeParse({ ...raw, github: { ...github, unknown: "claim" } }).success).toBe(
    false,
  );
  expect(sessionSchema.safeParse({ ...raw, provider: "unknown" }).success).toBe(false);
});
