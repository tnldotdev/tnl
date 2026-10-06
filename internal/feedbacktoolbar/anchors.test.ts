// @vitest-environment jsdom
import { afterEach, expect, test, vi } from "vitest";
import {
  capturePoint,
  captureSelection,
  resolveElement,
  restoreAnchor,
  selectorAlternatives,
  supportedAnchor,
} from "./anchors.ts";
import { createFeedbackAPI } from "./api.ts";

afterEach(() => {
  document.body.replaceChildren();
  document.getSelection()?.removeAllRanges();
});

test("selector alternatives include ID, structural, and class paths with escaped identifiers", () => {
  document.body.innerHTML =
    '<div id="pricing:a"><article class="card:a"><h3>One</h3></article><article class="card:b"><h3 class="title">Two</h3></article></div>';
  const heading = document.querySelector("article:last-child h3");
  if (!heading) throw new Error("missing fixture");
  const selectors = selectorAlternatives(heading);
  expect(selectors.length).toBeGreaterThan(1);
  expect(selectors.some((selector) => selector.includes(".title"))).toBe(true);
  for (const selector of selectors) expect(document.querySelector(selector)).toBe(heading);
});

test("relative coordinates and the cached element survive resize and sibling insertion", () => {
  document.body.innerHTML = "<div><button>One</button><button>Two</button></div>";
  const element = document.querySelector("button:last-child");
  if (!element) throw new Error("missing fixture");
  vi.spyOn(element, "getBoundingClientRect").mockReturnValue(new DOMRect(20, 30, 100, 50));
  const target = capturePoint(element, 45, 70);
  if (!target) throw new Error("missing anchor");
  expect(target.anchor).toMatchObject({ schema_version: 1, x: 0.25, y: 0.8 });
  const first = restoreAnchor(document, target.anchor);
  element.parentElement?.prepend(document.createElement("button"));
  expect(restoreAnchor(document, target.anchor, first)?.element).toBe(element);
  expect(
    resolveElement(document, ["[bad", "button", target.anchor.selectors[0] ?? "body"]),
  ).toBeTruthy();
});

test("text boundaries distinguish the direct text child from UTF-16 offsets", () => {
  document.body.innerHTML = '<p id="intro">Hello <!--ignore--><strong>world</strong>!</p>';
  const text = document.querySelector("strong")?.firstChild;
  if (!text) throw new Error("missing fixture");
  const range = document.createRange();
  range.setStart(text, 1);
  range.setEnd(text, 4);
  document.getSelection()?.addRange(range);
  const target = captureSelection(document);
  if (!target) throw new Error("missing selection anchor");
  expect(target.anchor.selection).toMatchObject({
    start: { text_node: 0, offset: 1 },
    end: { text_node: 0, offset: 4 },
    text: "orl",
  });
  expect(restoreAnchor(document, target.anchor)?.range?.toString()).toBe("orl");
  text.textContent = "Xworld";
  const restored = restoreAnchor(document, target.anchor);
  expect(restored?.range?.toString()).toBe("wor");
  expect(restored?.textChanged).toBe(true);
  expect(target.anchor.selection?.text).toBe("orl");
});

test("cross-element selection and invalid offsets retain an element fallback", () => {
  document.body.innerHTML = '<p id="intro">A🙂 <strong>world</strong> end</p>';
  const paragraph = document.querySelector("p"),
    start = paragraph?.firstChild,
    end = document.querySelector("strong")?.firstChild;
  if (!start || !end || !paragraph) throw new Error("missing fixture");
  const range = document.createRange();
  range.setStart(start, 1);
  range.setEnd(end, 5);
  document.getSelection()?.addRange(range);
  const target = captureSelection(document);
  if (!target) throw new Error("missing selection");
  expect(target.anchor.selection?.text).toBe("🙂 world");
  expect(restoreAnchor(document, target.anchor)?.range?.toString()).toBe("🙂 world");
  end.textContent = "w";
  const restored = restoreAnchor(document, target.anchor);
  expect(restored?.element).toBe(paragraph);
  expect(restored?.range).toBeUndefined();
  expect(restored?.textChanged).toBe(true);
});

test("element-container boundaries normalize to text offsets", () => {
  document.body.innerHTML = '<p id="intro">Hello <strong>world</strong>!</p>';
  const paragraph = document.querySelector("p");
  if (!paragraph) throw new Error("missing fixture");
  const range = document.createRange();
  range.setStart(paragraph, 1);
  range.setEnd(paragraph, 2);
  document.getSelection()?.addRange(range);
  const target = captureSelection(document);
  expect(target?.anchor.selection?.text).toBe("world");
  expect(target?.anchor.selection?.start.offset).toBe(0);
  expect(target?.anchor.selection?.end.offset).toBe(5);
});

test("unsupported anchor versions preserve readable comments and fail only placement", async () => {
  const anchor = { schema_version: 2, future_locator: "example" };
  const api = createFeedbackAPI(
    vi.fn<typeof fetch>().mockResolvedValue(
      Response.json({
        schema_version: 1,
        threads: [
          {
            schema_version: 1,
            message_count: 1,
            latest_event_cursor: 1,
            id: "fb_0123456789abcdefghijkl",
            state: "open",
            report: { text: "Still readable", created_at: "2026-10-05T00:00:00Z" },
            scope: { page_path: "/" },
            anchor,
          },
        ],
        event_cursor: 1,
      }),
    ),
  );
  const page = await api.list("/", undefined, new AbortController().signal);
  expect(page.threads[0]?.report.text).toBe("Still readable");
  expect(supportedAnchor(page.threads[0]?.anchor)).toBeUndefined();
});
