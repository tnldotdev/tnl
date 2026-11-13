import { expect, test } from "vitest";
import type { FeedbackEvent } from "./model.ts";
import { mergeEvents } from "./queries.ts";

test("event ordering and deduplication preserve decimal cursors above the safe integer limit", () => {
  const event = (cursor: string): FeedbackEvent => ({
    schema_version: 1,
    cursor,
    feedback_id: "fb_0123456789abcdefghijkl",
    type: "reply",
    actor: "reviewer",
    at: "2026-10-05T00:00:00Z",
  });
  const before = [event("9007199254740993"), event("9")];
  const added = [event("10"), event("9007199254740992"), event("9007199254740993")];
  expect(mergeEvents(before, added).map((value) => value.cursor)).toEqual([
    "9",
    "10",
    "9007199254740992",
    "9007199254740993",
  ]);
});
