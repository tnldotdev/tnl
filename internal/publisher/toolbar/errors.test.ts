import { expect, test } from "vitest";
import { createFeedbackAPI } from "./api.ts";
import { retryFeedback, safeFeedbackMessage } from "./errors.ts";

test("network failures keep their cause without rendering it", async () => {
  const cause = new Error("private-test-secret");
  const api = createFeedbackAPI(async () => {
    throw cause;
  });
  const error: unknown = await api
    .list(undefined, undefined, new AbortController().signal)
    .catch((error: unknown) => error);
  expect(error).toMatchObject({ code: "unavailable", cause });
  expect(safeFeedbackMessage(error)).not.toContain("private-test-secret");
  expect(retryFeedback(0, error)).toBe(true);
  expect(retryFeedback(2, error)).toBe(false);
});

test.each([
  [403, "access_expired"],
  [409, "conflict"],
  [400, "input_invalid"],
  [404, "not_found"],
])("does not retry expected HTTP %s failures", async (status, code) => {
  const api = createFeedbackAPI(
    async () => new Response("private-test-secret", { status: Number(status) }),
  );
  const error: unknown = await api
    .list(undefined, undefined, new AbortController().signal)
    .catch((error: unknown) => error);
  expect(error).toMatchObject({ code, retryable: false });
  expect(retryFeedback(0, error)).toBe(false);
  expect(safeFeedbackMessage(error)).not.toContain("private-test-secret");
});

test("invalid JSON is a response failure instead of a raw syntax error", async () => {
  const api = createFeedbackAPI(async () => new Response("private-test-secret"));
  await expect(api.list(undefined, undefined, new AbortController().signal)).rejects.toMatchObject({
    code: "response_invalid",
    retryable: false,
    cause: expect.any(SyntaxError),
  });
});
