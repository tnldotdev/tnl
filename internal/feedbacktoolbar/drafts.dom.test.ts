import { afterEach, expect, test } from "vitest";
import { recoverTarget, restoreDraft, saveDraft, type Recovery } from "./drafts.ts";

const draft: Recovery = {
  mode: "report",
  text: "Unsent",
  name: "Sam",
  activity: true,
  uncertain: false,
  anchor: { schema_version: 1, selectors: ["#save"], x: 0, y: 0 },
};
afterEach(() => {
  document.body.replaceChildren();
  window.sessionStorage.clear();
  window.history.replaceState(null, "", "/");
});

test("drafts are bounded, expiring, validated, one-use and scoped to the full page path and query", () => {
  window.history.replaceState(null, "", "/review?tab=one");
  expect(saveDraft(document, draft, 1000)).toBe(true);
  expect(restoreDraft(document, 1001)).toEqual(draft);
  expect(restoreDraft(document, 1001)).toBeUndefined();
  expect(saveDraft(document, { ...draft, text: "🙂".repeat(1001) }, 1000)).toBe(false);
  expect(saveDraft(document, draft, 1000)).toBe(true);
  expect(restoreDraft(document, 1000 + 15 * 60_000)).toBeUndefined();
  saveDraft(document, draft, 1000);
  window.history.replaceState(null, "", "/review?tab=two");
  expect(restoreDraft(document, 1001)).toBeUndefined();
  for (const value of [
    "not-json",
    JSON.stringify({
      version: 1,
      url: document.location.href,
      expires: 10000,
      draft: { ...draft, activity: null },
    }),
    " ".repeat(20_000),
  ]) {
    window.sessionStorage.setItem("tnl.feedback.unsent.v1", value);
    expect(restoreDraft(document, 1001)).toBeUndefined();
  }
});

test("restoring rechecks anchors and captures new safe evidence instead of restoring old HTML", () => {
  document.body.innerHTML = `<button id="save" onclick="steal()">Changed label<input value="private" /></button>`;
  const target = recoverTarget(document, draft.mode === "report" ? draft.anchor : undefined);
  expect(target?.element.label).toBe("Changed label");
  expect(target?.element.html).not.toContain("onclick");
  expect(target?.element.html).not.toContain("private");
  document.querySelector("#save")?.remove();
  expect(
    recoverTarget(document, draft.mode === "report" ? draft.anchor : undefined),
  ).toBeUndefined();
});
