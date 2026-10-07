import { expect, test } from "vitest";
import { TnlError, safeTnlMessage, classifyTnlError } from "./dist/errors.js";
import { requestTunnelAssignment, readDevelopmentContext } from "./dist/internal/dev.js";
import { startTestBootstrap } from "./test-helper/bootstrap.js";

test("preserves transport causes while keeping messages safe", () => {
  const cause = new Error("Bearer private-test-secret");
  const error = classifyTnlError(cause, "sdk.dev_unavailable");
  expect(error).toMatchObject({
    code: "sdk.dev_unavailable",
    class: "unavailable",
    retry: "later",
    cause,
  });
  expect(error.cause).toBe(cause);
  expect(safeTnlMessage(error)).not.toContain("private-test-secret");
  expect(safeTnlMessage(cause)).not.toContain("private-test-secret");
  expect(classifyTnlError(error, "sdk.unexpected")).toBe(error);
});

test("does not interpolate invalid environment values", () => {
  expect(() => readDevelopmentContext({ TNL_DEV_PROTOCOL: "private-test-secret" })).toThrow(
    new TnlError("sdk.protocol_unsupported"),
  );
});

test.each([
  [409, "sdk.request_rejected", "after_change"],
  [503, "sdk.dev_unavailable", "later"],
])("classifies HTTP %s without exposing its body", async (status, code, retry) => {
  const bootstrap = await startTestBootstrap({
    status: Number(status),
    responseBody: "private-test-secret",
  });
  const socket = bootstrap.environment.TNL_DEV_SOCKET;
  if (socket === undefined) throw new Error("test bootstrap did not return a socket");
  const error: unknown = await requestTunnelAssignment("vite", { socket }).catch(
    (error: unknown) => error,
  );
  expect(error).toMatchObject({ code, retry });
  expect(safeTnlMessage(error)).not.toContain("private-test-secret");
});
