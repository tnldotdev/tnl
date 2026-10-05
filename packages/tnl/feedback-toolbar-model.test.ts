import { expect, test } from "vitest";
import {
  parseEvents,
  parseFailedRequests,
  parseSummaries,
} from "../../internal/feedbacktoolbar/model.ts";

test("the feedback toolbar validates page threads before displaying reviewer text", () => {
  const threads = parseSummaries({
    threads: [
      {
        id: "fb_123",
        state: "ready_for_recheck",
        report: { text: "Save still fails", created_at: "2026-10-05T00:00:00Z" },
        element: {
          kind: "element",
          label: "Save",
          test_id: "save",
          html: "<script>bad()</script>",
        },
      },
      {
        id: "broken",
        state: "unexpected",
        report: { text: "forged" },
        element: { kind: "element" },
      },
    ],
  });
  expect(threads).toEqual([
    {
      id: "fb_123",
      state: "ready_for_recheck",
      report: { text: "Save still fails", created_at: "2026-10-05T00:00:00Z" },
      element: { kind: "element", role: undefined, label: "Save", test_id: "save" },
    },
  ]);
  expect(parseSummaries({ threads: "not a list" })).toEqual([]);
});

test("the evidence view keeps at most twenty validated failed requests", () => {
  const failedRequests = Array.from({ length: 22 }, (_, index) => ({
    method: "GET",
    path: `/api/${index}`,
    status: 500,
    duration_ms: index,
  }));
  const result = parseFailedRequests({
    failed_requests: [...failedRequests, { method: 5, path: "/secret" }],
  });
  expect(result).toHaveLength(20);
  expect(result[0]).toEqual(failedRequests[0]);
  expect(parseFailedRequests({ failed_requests: "not a list" })).toEqual([]);
  expect(
    parseEvents({
      events: [
        { cursor: 41, type: "reply", at: "2026-10-05T00:00:00Z", text: "please retry" },
        { cursor: "42", type: "reply" },
      ],
    }),
  ).toEqual([{ cursor: 41, type: "reply", at: "2026-10-05T00:00:00Z", text: "please retry" }]);
});
