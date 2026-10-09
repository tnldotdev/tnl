/** @jsxImportSource preact */
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/preact";
import { userEvent } from "@testing-library/user-event";
import { afterEach, expect, test, vi } from "vitest";
import type { FeedbackAPI } from "./api.ts";
import { Toolbar } from "./toolbar.tsx";
import type { FeedbackEvent, Summary, Thread } from "./model.ts";
import { FeedbackError } from "./errors.ts";

const id = "fb_0123456789abcdefghijkl";
const report: Thread = {
  schema_version: 1,
  id,
  state: "open",
  message_count: 1,
  latest_event_cursor: 1,
  scope: { page_path: "/" },
  report: { text: "Please use a clearer label", created_at: "2026-10-05T00:00:00Z" },
  evidence: { schema_version: 1, actions: [], failed_requests: [] },
};
const created: FeedbackEvent = {
  schema_version: 1,
  cursor: 1,
  feedback_id: id,
  type: "thread.created",
  actor: "reviewer",
  at: "2026-10-05T00:00:00Z",
};
function fixture(threads: Summary[] = []): FeedbackAPI {
  return {
    access: vi.fn<FeedbackAPI["access"]>().mockResolvedValue({
      require_sign_in: false,
      sign_in_available: true,
      identity_state: "anonymous",
    }),
    session: vi.fn<FeedbackAPI["session"]>().mockResolvedValue({ signed_in: false }),
    signOut: vi.fn<FeedbackAPI["signOut"]>().mockResolvedValue(undefined),
    list: vi
      .fn<FeedbackAPI["list"]>()
      .mockResolvedValue({ schema_version: 1, threads, event_cursor: 1 }),
    inspect: vi.fn<FeedbackAPI["inspect"]>().mockResolvedValue(report),
    events: vi
      .fn<FeedbackAPI["events"]>()
      .mockResolvedValue({ schema_version: 1, events: [created], event_cursor: 1 }),
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
function appButton(): HTMLButtonElement {
  const button = document.createElement("button");
  button.id = "save";
  button.textContent = "Save";
  document.body.append(button);
  return button;
}
async function openDraft(
  user: ReturnType<typeof userEvent.setup>,
  element: Element,
): Promise<void> {
  await user.click(screen.getByRole("button", { name: "Comment", exact: true }));
  await user.click(element);
  await screen.findByRole("textbox", { name: "Feedback", exact: true });
}
async function openThread(user: ReturnType<typeof userEvent.setup>): Promise<void> {
  await user.click(screen.getByRole("button", { name: "Feedback", exact: true }));
  await user.click(await screen.findByRole("button", { name: `View ${report.report.text}` }));
  await screen.findByRole("button", { name: "Resolve", exact: true });
}
afterEach(() => {
  act(() => cleanup());
  document.body.replaceChildren();
  document.getSelection()?.removeAllRanges();
  window.history.replaceState(null, "", "/");
  vi.unstubAllGlobals();
});

test("a signed-in visitor sends feedback under the account name instead of an unverified name", async () => {
  const api = fixture();
  vi.mocked(api.access).mockResolvedValue({
    require_sign_in: false,
    sign_in_available: true,
    identity_state: "signed_in",
    identity: { identity_id: "sam", display_name: "Sam" },
  });
  const { user } = mount(api);
  await screen.findByText("signed in as Sam");
  await openDraft(user, appButton());
  expect(screen.queryByRole("textbox", { name: /name \(optional/i })).toBeNull();
  await user.type(
    screen.getByRole("textbox", { name: "Feedback", exact: true }),
    "Suggestion from Sam",
  );
  await user.click(screen.getByRole("button", { name: "send feedback" }));
  await waitFor(() => expect(api.report).toHaveBeenCalledTimes(1));
  expect(vi.mocked(api.report).mock.calls[0]?.[0].display_name).toBe("");
});

test("required sign-in gates reports, replies, resolve and reopen while lists and history remain readable", async () => {
  const api = fixture([report]);
  vi.mocked(api.access).mockResolvedValue({
    require_sign_in: true,
    sign_in_available: true,
    identity_state: "anonymous",
  });
  const { user } = mount(api);
  await openDraft(user, appButton());
  await user.type(screen.getByRole("textbox", { name: "Feedback", exact: true }), "Unsent");
  expect(screen.getByRole("button", { name: "send feedback" }).hasAttribute("disabled")).toBe(true);
  await user.click(screen.getByRole("button", { name: "cancel", exact: true }));
  await openThread(user);
  expect(screen.getByRole("heading", { name: report.report.text })).toBeTruthy();
  await user.type(screen.getByRole("textbox", { name: "Reply", exact: true }), "Unsent reply");
  expect(screen.getByRole("button", { name: "Send reply" }).hasAttribute("disabled")).toBe(true);
  expect(
    screen.getByRole("button", { name: "Resolve", exact: true }).hasAttribute("disabled"),
  ).toBe(true);
  vi.mocked(api.inspect).mockResolvedValue({ ...report, state: "resolved" });
  const reopen = await screen.findByRole(
    "button",
    { name: "Reopen", exact: true },
    { timeout: 4000 },
  );
  expect(reopen.hasAttribute("disabled")).toBe(true);
  expect(api.append).not.toHaveBeenCalled();
  expect(api.report).not.toHaveBeenCalled();
});

test("live policy polling gates an open draft without losing its text and preflight prevents stale policy writes", async () => {
  const { api, user } = mount();
  await openDraft(user, appButton());
  await user.type(
    screen.getByRole("textbox", { name: "Feedback", exact: true }),
    "Keep this draft",
  );
  vi.mocked(api.access).mockResolvedValue({
    require_sign_in: true,
    sign_in_available: true,
    identity_state: "anonymous",
  });
  await user.click(screen.getByRole("button", { name: "send feedback" }));
  await screen.findByRole("alert");
  expect(api.report).not.toHaveBeenCalled();
  expect(
    (screen.getByRole("textbox", { name: "Feedback", exact: true }) as HTMLTextAreaElement).value,
  ).toBe("Keep this draft");
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "send feedback" }).hasAttribute("disabled")).toBe(
      true,
    ),
  );
  vi.mocked(api.access).mockResolvedValue({
    require_sign_in: false,
    sign_in_available: false,
    identity_state: "anonymous",
  });
  await waitFor(
    () =>
      expect(screen.getByRole("button", { name: "send feedback" }).hasAttribute("disabled")).toBe(
        false,
      ),
    { timeout: 4000 },
  );
});

test("unknown identity and policy never claim anonymous or verified posting while feedback remains readable", async () => {
  const api = fixture([report]);
  vi.mocked(api.access).mockRejectedValue(new FeedbackError("unavailable"));
  const { user } = mount(api);
  await openThread(user);
  expect(screen.getByRole("heading", { name: report.report.text })).toBeTruthy();
  expect(screen.queryByText(/posting as|posting anonymously|signed in as/)).toBeNull();
  expect(
    screen.getByRole("button", { name: "Resolve", exact: true }).hasAttribute("disabled"),
  ).toBe(true);
});

test("toolbar sign-in opens another tab without replacing the report draft", async () => {
  window.history.replaceState(null, "", "/review?tab=one");
  const api = fixture();
  vi.mocked(api.access).mockResolvedValue({
    require_sign_in: true,
    sign_in_available: true,
    identity_state: "expired",
  });
  const { user } = mount(api);
  await openDraft(user, appButton());
  await user.type(
    screen.getByRole("textbox", { name: "Feedback", exact: true }),
    "Draft stays on this page",
  );
  const link = within(screen.getByRole("region", { name: "New feedback" })).getByRole("link", {
    name: /sign in/,
  });
  expect(link.getAttribute("href")).toBe("/__tnl/team/login?return=%2Freview%3Ftab%3Done");
  expect(link.getAttribute("target")).toBe("_blank");
  expect(link.getAttribute("rel")).toBe("noopener noreferrer");
  vi.mocked(api.access).mockResolvedValue({
    require_sign_in: true,
    sign_in_available: true,
    identity_state: "signed_in",
    identity: { identity_id: "sam", display_name: "Sam" },
  });
  await screen.findByText("signed in as Sam", {}, { timeout: 4000 });
  expect(
    (screen.getByRole("textbox", { name: "Feedback", exact: true }) as HTMLTextAreaElement).value,
  ).toBe("Draft stays on this page");
  expect(api.report).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "send feedback" }));
  await waitFor(() => expect(api.report).toHaveBeenCalledTimes(1));
  expect(vi.mocked(api.report).mock.calls[0]?.[0].evidence.element?.label).toBe("Save");
});

test("an uncertain retry cannot silently switch posting identity", async () => {
  const { api, user } = mount();
  vi.mocked(api.report).mockRejectedValueOnce(new FeedbackError("unavailable"));
  await openDraft(user, appButton());
  await user.type(
    screen.getByRole("textbox", { name: "Feedback", exact: true }),
    "Uncertain submission",
  );
  await user.click(screen.getByRole("button", { name: "send feedback" }));
  await screen.findByRole("alert");
  vi.mocked(api.access).mockResolvedValue({
    require_sign_in: false,
    sign_in_available: true,
    identity_state: "signed_in",
    identity: { identity_id: "sam", display_name: "Sam" },
  });
  await screen.findByText("signed in as Sam", {}, { timeout: 4000 });
  expect(screen.getByRole("button", { name: "send feedback" }).hasAttribute("disabled")).toBe(true);
  expect(api.report).toHaveBeenCalledTimes(1);
});

test("editing after an uncertain submission keeps the draft but uses a new retry key", async () => {
  const { api, user } = mount();
  vi.mocked(api.report).mockRejectedValueOnce(new FeedbackError("unavailable"));
  await openDraft(user, appButton());
  await user.type(
    screen.getByRole("textbox", { name: "Feedback", exact: true }),
    "Possibly submitted",
  );
  await user.click(screen.getByRole("button", { name: "send feedback" }));
  await screen.findByRole("alert");
  expect(
    screen.getByText("this may have been sent; check the feedback list before editing."),
  ).toBeTruthy();
  expect((screen.getByRole("textbox", { name: "Feedback" }) as HTMLTextAreaElement).value).toBe(
    "Possibly submitted",
  );
  expect(api.report).toHaveBeenCalledTimes(1);
  await user.click(screen.getByRole("button", { name: "edit draft" }));
  await user.click(screen.getByRole("button", { name: "send feedback" }));
  await waitFor(() => expect(api.report).toHaveBeenCalledTimes(2));
  expect(vi.mocked(api.report).mock.calls[0]?.[1]).not.toBe(
    vi.mocked(api.report).mock.calls[1]?.[1],
  );
});

test("placement creates only a local draft, prevents app activation, and sends subtle context", async () => {
  const { api, user } = mount();
  const app = appButton();
  const clicked = vi.fn();
  app.addEventListener("click", clicked);
  await openDraft(user, app);
  expect(clicked).not.toHaveBeenCalled();
  expect(api.report).not.toHaveBeenCalled();
  await user.type(
    screen.getByRole("textbox", { name: "Feedback", exact: true }),
    "Improve this label",
  );
  await user.click(screen.getByText(/^context/));
  await screen.findByText(/POST \/api/);
  expect(screen.queryByText(/"selectors"/)).toBeNull();
  await user.click(screen.getByRole("checkbox", { name: "Include activity" }));
  await user.click(screen.getByRole("button", { name: "send feedback", exact: true }));
  await waitFor(() => expect(api.report).toHaveBeenCalledTimes(1));
  expect(vi.mocked(api.report).mock.calls[0]?.[0]).toMatchObject({
    schema_version: 1,
    text: "Improve this label",
    anchor: { schema_version: 1, selectors: expect.arrayContaining(["#save"]) },
    evidence: { actions: [], failed_requests: [] },
  });
});

test("cancel discards an unsent draft without creating a server thread", async () => {
  const { api, user } = mount();
  await openDraft(user, appButton());
  await user.type(screen.getByRole("textbox", { name: "Feedback", exact: true }), "Unsent");
  await user.click(screen.getByRole("button", { name: "cancel", exact: true }));
  expect(api.report).not.toHaveBeenCalled();
  expect(screen.queryByRole("textbox", { name: "Feedback", exact: true })).toBeNull();
});

test("a lost response retries the frozen report with its original idempotency key", async () => {
  const { api, user } = mount();
  vi.mocked(api.report).mockRejectedValueOnce(new Error("try again"));
  await openDraft(user, appButton());
  await user.type(
    screen.getByRole("textbox", { name: "Feedback", exact: true }),
    "Copy suggestion",
  );
  await user.click(await screen.findByRole("button", { name: "send feedback", exact: true }));
  await screen.findByRole("alert");
  await user.click(screen.getByRole("button", { name: "send feedback", exact: true }));
  await waitFor(() => expect(api.report).toHaveBeenCalledTimes(2));
  const [first, second] = vi.mocked(api.report).mock.calls;
  expect(first?.slice(0, 2)).toEqual(second?.slice(0, 2));
});

test("reply, resolve, and reopen share the same conversation and preserve history", async () => {
  const { api, user } = mount(fixture([report]));
  await openThread(user);
  await user.type(screen.getByRole("textbox", { name: "Reply", exact: true }), "Thanks");
  await user.click(screen.getByRole("button", { name: "Send reply" }));
  await waitFor(() =>
    expect(api.append).toHaveBeenCalledWith(
      id,
      "reply",
      "Thanks",
      expect.any(String),
      expect.any(AbortSignal),
      "anonymous",
    ),
  );
  vi.mocked(api.append).mockImplementationOnce(async () => {
    vi.mocked(api.inspect).mockResolvedValue({ ...report, state: "resolved" });
    return { ...created, cursor: 3, type: "thread.resolved" };
  });
  await user.click(screen.getByRole("button", { name: "Resolve", exact: true }));
  await screen.findByRole("button", { name: "Reopen", exact: true });
  expect(screen.queryByRole("button", { name: "Send reply" })).toBeNull();
  vi.mocked(api.append).mockImplementationOnce(async () => {
    vi.mocked(api.inspect).mockResolvedValue(report);
    return { ...created, cursor: 4, type: "thread.reopened" };
  });
  await user.click(screen.getByRole("button", { name: "Reopen", exact: true }));
  await screen.findByRole("button", { name: "Send reply" });
  expect(
    within(screen.getByRole("list", { name: "History" })).getAllByRole("listitem"),
  ).toHaveLength(4);
});

test("page and status filters are sent to the hostname-scoped API", async () => {
  const { api, user } = mount(fixture([report]));
  await user.click(screen.getByRole("button", { name: "Feedback", exact: true }));
  await user.selectOptions(screen.getByRole("combobox", { name: "pages" }), "all");
  await waitFor(() =>
    expect(api.list).toHaveBeenCalledWith(undefined, undefined, expect.any(AbortSignal), "open"),
  );
  await user.selectOptions(screen.getByRole("combobox", { name: "status" }), "resolved");
  await waitFor(() =>
    expect(api.list).toHaveBeenCalledWith(
      undefined,
      undefined,
      expect.any(AbortSignal),
      "resolved",
    ),
  );
});

test("a missing anchor keeps its conversation readable without a reattachment action", async () => {
  const missing = {
    ...report,
    anchor: { schema_version: 1 as const, selectors: ["#removed"], x: 0.5, y: 0.5 },
  };
  const { user } = mount(fixture([missing]));
  await openThread(user);
  expect(screen.getByText(/element is no longer/)).toBeTruthy();
  expect(screen.getByRole("heading", { name: report.report.text })).toBeTruthy();
  expect(screen.queryByRole("button", { name: /place|reattach/i })).toBeNull();
});

test("polling updates replies and status without a refresh control or lost draft", async () => {
  const { api, user } = mount(fixture([report]));
  await openThread(user);
  const textarea = screen.getByRole("textbox", { name: "Reply", exact: true });
  await user.type(textarea, "Draft");
  vi.mocked(api.events).mockResolvedValueOnce({
    schema_version: 1,
    events: [{ ...created, cursor: 2, type: "reply", text: "Remote reply" }],
    event_cursor: 2,
  });
  vi.mocked(api.inspect).mockResolvedValueOnce({ ...report, state: "resolved" });
  await waitFor(() => expect(screen.getByText("Remote reply")).toBeTruthy(), { timeout: 4000 });
  await screen.findByRole("button", { name: "Reopen", exact: true });
  expect((textarea as HTMLTextAreaElement).value).toBe("Draft");
  expect(document.activeElement).toBe(textarea);
  expect(screen.queryByRole("button", { name: /refresh/i })).toBeNull();
  const calls = vi.mocked(api.events).mock.calls.length;
  await user.click(screen.getByRole("button", { name: "back to list" }));
  await new Promise((resolve) => setTimeout(resolve, 2100));
  expect(vi.mocked(api.events).mock.calls).toHaveLength(calls);
});

test("there are no comment or hide keyboard shortcuts", async () => {
  mount();
  fireEvent.keyDown(document, { key: "c" });
  fireEvent.keyDown(document, { key: ".", metaKey: true });
  expect(screen.queryByRole("complementary", { name: "new feedback" })).toBeNull();
  expect(screen.getByRole("button", { name: "Feedback", exact: true })).toBeTruthy();
});
