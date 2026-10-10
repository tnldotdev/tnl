import { expect, test } from "vitest";
import { safeTnlMessage, classifyTnlError } from "./dist/errors.js";

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
