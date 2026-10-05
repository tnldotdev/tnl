// @vitest-environment jsdom
/** @jsxImportSource preact */
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/preact";
import { userEvent } from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import type { FeedbackAPI } from "./api.ts";
import { Toolbar } from "./toolbar.tsx";
import type { FeedbackEvent, Summary, Thread, ThreadPage } from "./model.ts";

const id = "fb_0123456789abcdefghijkl";
const otherID = "fb_abcdefghijkl0123456789";
const report: Thread = {
  id,
  state: "open",
  scope: { page_path: "/" },
  report: { text: "Please use a clearer label", created_at: "2026-10-05T00:00:00Z" },
  element: { kind: "page" },
  evidence: { actions: [], failed_requests: [] },
};
const created: FeedbackEvent = {
  cursor: 1,
  feedback_id: id,
  type: "thread.created",
  actor: "reviewer",
  at: "2026-10-05T00:00:00Z",
};
function fixture(threads: Summary[] = []): FeedbackAPI {
  return {
    list: vi.fn<FeedbackAPI["list"]>().mockResolvedValue({ threads, event_cursor: 1 }),
    inspect: vi.fn<FeedbackAPI["inspect"]>().mockResolvedValue(report),
    events: vi
      .fn<FeedbackAPI["events"]>()
      .mockResolvedValue({ events: [created], event_cursor: 1 }),
    evidence: vi
      .fn<FeedbackAPI["evidence"]>()
      .mockResolvedValue([{ method: "POST", path: "/api", status: 500, duration_ms: 25 }]),
    report: vi.fn<FeedbackAPI["report"]>().mockResolvedValue(report),
    append: vi.fn<FeedbackAPI["append"]>().mockImplementation(async (_, type, text) => ({
      ...created,
      cursor: 2,
      type,
      ...(text ? { text } : {}),
    })),
  };
}
function mount(api = fixture()) {
  const host = document.createElement("div");
  document.body.append(host);
  const view = render(<Toolbar api={api} document={document} host={host} />, { container: host });
  return { api, host, ...view, user: userEvent.setup() };
}
afterEach(() => {
  cleanup();
  document.body.replaceChildren();
  window.history.replaceState(null, "", "/");
});

test("reviews a frozen evidence bundle before posting, with explicit activity consent", async () => {
  const { api, user } = mount();
  await user.click(screen.getByRole("button", { name: "Feedback", exact: true }));
  await screen.findByText("No feedback on this page yet.");
  const appButton = document.createElement("button");
  appButton.textContent = "Save changes";
  document.body.append(appButton);
  await user.click(appButton);
  await user.type(screen.getByLabelText("Feedback", { exact: true }), "Please improve this label");
  await user.click(screen.getByRole("button", { name: "Review feedback" }));
  await screen.findByText("Evidence to send");
  expect(api.report).not.toHaveBeenCalled();
  expect(screen.getByText(/failed_requests/).textContent).toContain("Save changes");
  await user.click(screen.getByRole("button", { name: "Edit feedback" }));
  await user.click(screen.getByLabelText("Include recent actions and failed requests"));
  await user.click(screen.getByRole("button", { name: "Review feedback" }));
  await screen.findByRole("button", { name: "Send feedback" });
  await user.click(screen.getByRole("button", { name: "Send feedback" }));
  await waitFor(() => expect(api.report).toHaveBeenCalledTimes(1));
  expect(vi.mocked(api.report).mock.calls[0]?.[0]).toMatchObject({
    text: "Please improve this label",
    evidence: { actions: [], failed_requests: [] },
  });
});

test("a lost report response retries the same body and idempotency key", async () => {
  const { api, user } = mount();
  vi.mocked(api.report).mockRejectedValueOnce(new Error("try again"));
  await user.click(screen.getByRole("button", { name: "Feedback", exact: true }));
  await user.type(screen.getByLabelText("Feedback", { exact: true }), "Copy suggestion");
  await user.click(screen.getByRole("button", { name: "Review feedback" }));
  await user.click(await screen.findByRole("button", { name: "Send feedback" }));
  await screen.findByRole("alert");
  await user.click(screen.getByRole("button", { name: "Send feedback" }));
  await waitFor(() => expect(api.report).toHaveBeenCalledTimes(2));
  const [first, second] = vi.mocked(api.report).mock.calls;
  expect(first?.slice(0, 2)).toEqual(second?.slice(0, 2));
});

test("reply, resolve, and reopen are available in the same toolbar and retain history", async () => {
  const { api, user } = mount(fixture([report]));
  await user.click(screen.getByRole("button", { name: "Feedback", exact: true }));
  await user.click(await screen.findByRole("button", { name: report.report.text }));
  await screen.findByRole("button", { name: "Resolve", exact: true });
  await user.type(screen.getByLabelText("Reply", { exact: true }), "Thanks for the suggestion");
  await user.click(screen.getByRole("button", { name: "Send reply" }));
  await waitFor(() =>
    expect(api.append).toHaveBeenCalledWith(
      id,
      "reply",
      "Thanks for the suggestion",
      expect.any(String),
      expect.any(AbortSignal),
    ),
  );
  vi.mocked(api.append).mockResolvedValueOnce({ ...created, cursor: 3, type: "thread.resolved" });
  await user.click(screen.getByRole("button", { name: "Resolve", exact: true }));
  await screen.findByRole("button", { name: "Reopen", exact: true });
  expect(screen.queryByRole("button", { name: "Send reply" })).toBeNull();
  vi.mocked(api.append).mockResolvedValueOnce({ ...created, cursor: 4, type: "thread.reopened" });
  await user.click(screen.getByRole("button", { name: "Reopen", exact: true }));
  await screen.findByRole("button", { name: "Send reply" });
  const history = within(screen.getByRole("list", { name: "History" }));
  expect(history.getAllByRole("listitem")).toHaveLength(4);
  expect(screen.getByRole("heading", { name: report.report.text })).toBeTruthy();
});

test("list and history pagination append records instead of replacing them", async () => {
  const { api, user } = mount();
  vi.mocked(api.list)
    .mockResolvedValueOnce({ threads: [report], next_cursor: id, event_cursor: 2 })
    .mockResolvedValueOnce({
      threads: [
        { ...report, id: otherID, report: { ...report.report, text: "Another suggestion" } },
      ],
      event_cursor: 2,
    });
  vi.mocked(api.events)
    .mockResolvedValueOnce({ events: [created], next_cursor: 1, event_cursor: 2 })
    .mockResolvedValueOnce({
      events: [{ ...created, cursor: 2, type: "reply", text: "Following up" }],
      event_cursor: 2,
    });
  await user.click(screen.getByRole("button", { name: "Feedback", exact: true }));
  await user.click(await screen.findByRole("button", { name: "Load more feedback" }));
  await screen.findByRole("button", { name: "Another suggestion" });
  expect(screen.getByRole("button", { name: report.report.text })).toBeTruthy();
  await user.click(screen.getByRole("button", { name: report.report.text }));
  await user.click(await screen.findByRole("button", { name: "Load more history" }));
  await screen.findByText("Following up");
  expect(screen.getByText("Reported", { exact: true })).toBeTruthy();
});

test("refreshing or scrolling preserves the form node, focus, and draft", async () => {
  const { user } = mount();
  await user.click(screen.getByRole("button", { name: "Feedback", exact: true }));
  const textarea = screen.getByLabelText("Feedback", { exact: true });
  await user.type(textarea, "Draft feedback");
  fireEvent.scroll(document);
  fireEvent.resize(window);
  expect(document.activeElement).toBe(textarea);
  await user.click(screen.getByRole("button", { name: "Refresh feedback" }));
  await screen.findByText("No feedback on this page yet.");
  expect(screen.getByLabelText("Feedback", { exact: true })).toBe(textarea);
  expect((textarea as HTMLTextAreaElement).value).toBe("Draft feedback");
});

test("selecting an element prevents the app action and Escape cancels selection", async () => {
  const { user } = mount();
  const app = document.createElement("button");
  app.textContent = "Save";
  app.setAttribute("data-testid", "save");
  document.body.append(app);
  const listener = vi.fn();
  app.addEventListener("click", listener);
  await user.click(screen.getByRole("button", { name: "Feedback", exact: true }));
  await user.click(screen.getByRole("button", { name: "Select an element" }));
  await user.click(app);
  expect(listener).not.toHaveBeenCalled();
  await screen.findByText("Pinned: Save");
  await user.click(screen.getByRole("button", { name: "Select an element" }));
  await user.keyboard("{Escape}");
  expect(screen.queryByText(/Select an element on the page/)).toBeNull();
  await user.click(app);
  expect(listener).toHaveBeenCalledTimes(1);
});

test("closing the toolbar cancels requests and removes listeners", async () => {
  const { api, user, unmount } = mount();
  let resolve: ((page: ThreadPage) => void) | undefined;
  vi.mocked(api.list).mockImplementationOnce(
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  await user.click(screen.getByRole("button", { name: "Feedback", exact: true }));
  const signal = vi.mocked(api.list).mock.calls[0]?.[2];
  await user.click(screen.getByRole("button", { name: "Close feedback" }));
  expect(signal?.aborted).toBe(true);
  resolve?.({ threads: [report], event_cursor: 1 });
  expect(screen.queryByRole("button", { name: report.report.text })).toBeNull();
  unmount();
});

test("Escape closes the panel and restores focus to its toggle", async () => {
  const { user } = mount();
  const toggle = screen.getByRole("button", { name: "Feedback", exact: true });
  await user.click(toggle);
  await user.click(screen.getByLabelText("Feedback", { exact: true }));
  await user.keyboard("{Escape}");
  expect(screen.queryByRole("complementary", { name: "Preview feedback" })).toBeNull();
  expect(document.activeElement).toBe(toggle);
});

test("navigation cancels the old page load and cannot display its late response", async () => {
  const { api, user } = mount();
  let complete: ((page: ThreadPage) => void) | undefined;
  vi.mocked(api.list).mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        complete = resolve;
      }),
  );
  await user.click(screen.getByRole("button", { name: "Feedback", exact: true }));
  const oldSignal = vi.mocked(api.list).mock.calls[0]?.[2];
  window.history.pushState(null, "", "/other-page");
  await waitFor(() =>
    expect(api.list).toHaveBeenCalledWith("/other-page", undefined, expect.any(AbortSignal)),
  );
  expect(oldSignal?.aborted).toBe(true);
  complete?.({ threads: [report], event_cursor: 1 });
  await screen.findByText("No feedback on this page yet.");
  expect(screen.queryByRole("button", { name: report.report.text })).toBeNull();
});
