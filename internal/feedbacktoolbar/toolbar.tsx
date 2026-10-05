/** @jsx h */

import {
  parseEvents,
  parseFailedRequests,
  parseSummaries,
  record,
  type Action,
  type FailedRequest,
  type FeedbackEvent,
  type FeedbackSummary,
  type Pin,
} from "./model.ts";

export function h(
  tag: string,
  props: Record<string, unknown> | null,
  ...children: unknown[]
): HTMLElement {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(props ?? {})) {
    if (name === "onClick" && typeof value === "function")
      node.addEventListener("click", value as EventListener);
    else if (name === "onInput" && typeof value === "function")
      node.addEventListener("input", value as EventListener);
    else if (name === "onChange" && typeof value === "function")
      node.addEventListener("change", value as EventListener);
    else if (name === "className" && typeof value === "string") node.className = value;
    else if (name === "checked" && value === true) (node as HTMLInputElement).checked = true;
    else if (
      name === "value" &&
      (node instanceof HTMLInputElement || node instanceof HTMLTextAreaElement)
    )
      node.value = String(value ?? "");
    else if (value !== undefined && value !== null && value !== false)
      node.setAttribute(name, String(value));
  }
  const append = (child: unknown): void => {
    if (child === null || child === undefined || typeof child === "boolean") return;
    if (Array.isArray(child)) child.forEach(append);
    else if (child instanceof Node) node.append(child);
    else if (typeof child === "string" || typeof child === "number")
      node.append(document.createTextNode(String(child)));
  };
  children.forEach(append);
  return node;
}

const style = `
  :host { all: initial; color-scheme: light dark; font: 14px/1.4 system-ui, sans-serif; }
  * { box-sizing: border-box; }
  .toggle { position: fixed; bottom: 16px; right: 16px; z-index: 2147483647; border-radius: 999px; padding: 9px 16px; background: #1a2235; color: white; border: 1px solid #a5b4fc; cursor: pointer; }
  .panel { position: fixed; bottom: 62px; right: 16px; z-index: 2147483647; width: min(390px, calc(100vw - 32px)); max-height: min(85vh, 740px); overflow-y: auto; padding: 16px; border: 1px solid #9099aa; border-radius: 12px; background: #fff; color: #192238; box-shadow: 0 8px 35px #151c3166; }
  .panel h2 { margin: 0 0 8px; font: 600 17px/1.3 system-ui, sans-serif; }
  .panel p { margin: 7px 0; }
  .panel textarea, .panel input[type=text] { display: block; width: 100%; padding: 7px; margin: 7px 0; border: 1px solid #8892a7; border-radius: 5px; font: inherit; background: white; color: #192238; }
  .panel textarea { min-height: 72px; resize: vertical; }
  .panel button { font: inherit; padding: 5px 9px; margin: 4px 4px 4px 0; border-radius: 5px; border: 1px solid #63708a; color: #192238; background: #f4f6fa; cursor: pointer; }
  .panel button:disabled { opacity: .55; cursor: not-allowed; }
  .panel .primary { background: #1a2235; color: #fff; }
  .panel .error { color: #a01e2c; }
  .panel .thread { margin-top: 8px; border-top: 1px solid #cbd2de; padding-top: 8px; }
  .panel .detail { border-left: 2px solid #8f9bb2; padding-left: 8px; white-space: pre-wrap; }
  .panel .evidence { font: 12px/1.4 ui-monospace, monospace; overflow-wrap: anywhere; white-space: pre-wrap; background: #f5f6f8; padding: 7px; }
  .pin { position: fixed; z-index: 2147483646; border: 2px solid #e9a419; border-radius: 999px; width: 16px; height: 16px; background: #ffe4a6; pointer-events: none; }
`;

const root = document.createElement("div");
root.setAttribute("data-tnl-feedback", "");
document.documentElement.append(root);
const shadow = root.attachShadow({ mode: "closed" });
const styles = document.createElement("style");
styles.nonce =
  document.querySelector<HTMLScriptElement>('script[src^="/__tnl/feedback/toolbar."]')?.nonce ?? "";
styles.textContent = style;

const actions: Action[] = [{ type: "navigation", path: location.pathname }];
let threads: FeedbackSummary[] = [];
let nextThreadCursor: string | undefined;
let failures: FailedRequest[] = [];
let events: FeedbackEvent[] = [];
let nextEventCursor: number | undefined;
let selectedThread: FeedbackSummary | undefined;
let pin: Pin = { kind: "page" };
let open = location.hash === "#tnl-feedback";
let picking = false;
let owner = false;
let includeEvidence = true;
let message = "";
let displayName = "";
let reply = "";
let error = "";
let reportKey = crypto.randomUUID();
let eventKey = crypto.randomUUID();
let lastEventIdentity = "";

function pushAction(action: Action): void {
  actions.push(action);
  if (actions.length > 20) actions.shift();
}

function label(element: Element): string {
  return (element.getAttribute("aria-label") ?? element.textContent ?? "").trim().slice(0, 256);
}

function sanitizeHTML(element: Element): string {
  const clone = element.cloneNode(true);
  if (!(clone instanceof Element)) return "";
  const allowed = new Set([
    "id",
    "class",
    "role",
    "aria-label",
    "data-testid",
    "title",
    "name",
    "type",
  ]);
  const safeTags = new Set([
    "button",
    "div",
    "span",
    "p",
    "label",
    "form",
    "input",
    "textarea",
    "a",
    "strong",
    "em",
  ]);
  for (const node of [clone, ...clone.querySelectorAll("*")]) {
    if (
      node.tagName === "SCRIPT" ||
      node.tagName === "STYLE" ||
      node.tagName === "IFRAME" ||
      node.tagName === "SVG"
    ) {
      node.remove();
      continue;
    }
    for (const attribute of Array.from(node.attributes)) {
      if (!allowed.has(attribute.name)) node.removeAttribute(attribute.name);
    }
    if (node.tagName === "TEXTAREA" || node.tagName === "OPTION") node.textContent = "";
    if (!safeTags.has(node.tagName.toLowerCase()))
      node.replaceWith(document.createTextNode(node.textContent?.slice(0, 256) ?? ""));
  }
  return clone.outerHTML.slice(0, 4096);
}

function requestPin(element: Element): Pin {
  return {
    kind: "element",
    role: element.getAttribute("role") ?? element.tagName.toLowerCase(),
    label: label(element),
    test_id: element.getAttribute("data-testid") ?? undefined,
    html: sanitizeHTML(element),
  };
}

function pagePath(): string {
  return location.pathname + location.search;
}

async function api(path: string, init?: RequestInit): Promise<unknown> {
  const response = await fetch("/__tnl/feedback" + path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    cache: "no-store",
    ...init,
  });
  if (!response.ok)
    throw new Error(`tnl feedback returned ${response.status}; retry or check the share`);
  return (await response.json()) as unknown;
}

async function refresh(): Promise<void> {
  try {
    const [page, evidence, ownership] = await Promise.all([
      api("?path=" + encodeURIComponent(pagePath())),
      api("/evidence"),
      api("/owner"),
    ]);
    threads = parseSummaries(page);
    nextThreadCursor =
      typeof record(page)?.next_cursor === "string" ? String(record(page)?.next_cursor) : undefined;
    failures = parseFailedRequests(evidence);
    owner = record(ownership)?.owner === true;
    if (selectedThread)
      selectedThread = threads.find((thread) => thread.id === selectedThread?.id) ?? selectedThread;
    error = "";
  } catch (reason) {
    error = reason instanceof Error ? reason.message : "could not load feedback; retry";
  }
  render();
}

async function loadMoreThreads(): Promise<void> {
  if (!nextThreadCursor) return;
  try {
    const cursor = nextThreadCursor;
    const page = await api(
      "?path=" + encodeURIComponent(pagePath()) + "&cursor=" + encodeURIComponent(cursor),
    );
    threads = [...threads, ...parseSummaries(page)];
    const next = record(page)?.next_cursor;
    nextThreadCursor = typeof next === "string" && next !== cursor ? next : undefined;
    error = "";
  } catch (reason) {
    error = reason instanceof Error ? reason.message : "could not load more feedback; retry";
  }
  render();
}

async function openThread(thread: FeedbackSummary): Promise<void> {
  selectedThread = thread;
  lastEventIdentity = "";
  events = [];
  nextEventCursor = undefined;
  await loadMoreEvents();
}

async function loadMoreEvents(): Promise<void> {
  if (!selectedThread) return;
  try {
    const cursor = nextEventCursor === undefined ? "" : "?after_cursor=" + nextEventCursor;
    const page = await api("/" + encodeURIComponent(selectedThread.id) + "/events" + cursor);
    events = [...events, ...parseEvents(page)];
    const value = record(page)?.next_cursor;
    nextEventCursor =
      typeof value === "number" && value > (nextEventCursor ?? 0) ? value : undefined;
  } catch (reason) {
    error = reason instanceof Error ? reason.message : "could not load replies; retry";
  }
  render();
}

async function submit(): Promise<void> {
  if (!message.trim()) {
    error = "write what you noticed before submitting";
    render();
    return;
  }
  try {
    const evidence = includeEvidence
      ? { actions: actions.slice(-20), failed_requests: failures.slice(-20) }
      : { actions: [], failed_requests: [] };
    const result = record(
      await api("", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": reportKey },
        body: JSON.stringify({
          text: message.trim().slice(0, 4000),
          display_name: displayName.trim().slice(0, 64),
          page_path: pagePath(),
          element: pin,
          evidence,
        }),
      }),
    );
    if (typeof result?.id !== "string")
      throw new Error("server returned an invalid feedback thread");
    message = "";
    pin = { kind: "page" };
    reportKey = crypto.randomUUID();
    await refresh();
    const created = threads.find((thread) => thread.id === result.id);
    if (created) await openThread(created);
  } catch (reason) {
    error = reason instanceof Error ? reason.message : "could not submit feedback; retry";
    render();
  }
}

async function sendEvent(
  type: "reply" | "fix.ready_for_recheck" | "thread.resolved" | "recheck.still_broken",
): Promise<void> {
  if (!selectedThread) return;
  if ((type === "reply" || type === "fix.ready_for_recheck") && !reply.trim()) {
    error = "write a reply before continuing";
    render();
    return;
  }
  const identity = `${selectedThread.id}\0${type}\0${reply.trim()}`;
  if (identity !== lastEventIdentity) {
    eventKey = crypto.randomUUID();
    lastEventIdentity = identity;
  }
  try {
    await api("/" + encodeURIComponent(selectedThread.id) + "/events", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": eventKey },
      body: JSON.stringify({ type, text: reply.trim().slice(0, 4000) }),
    });
    reply = "";
    eventKey = crypto.randomUUID();
    lastEventIdentity = "";
    await refresh();
    if (selectedThread) await openThread(selectedThread);
  } catch (reason) {
    error = reason instanceof Error ? reason.message : "could not update feedback; retry";
    render();
  }
}

function matchedElement(thread: FeedbackSummary): Element | undefined {
  if (thread.element.kind !== "element" || !thread.element.test_id) return undefined;
  const matches = document.querySelectorAll(
    `[data-testid="${CSS.escape(thread.element.test_id)}"]`,
  );
  const element = matches.item(0);
  if (matches.length !== 1 || !element || label(element) !== thread.element.label) return undefined;
  return element;
}

function renderPins(): HTMLElement[] {
  const pins: HTMLElement[] = [];
  for (const thread of threads) {
    const element = matchedElement(thread);
    if (!element) continue;
    const bounds = element.getBoundingClientRect();
    const marker = <span className="pin" aria-hidden="true" />;
    marker.style.top = Math.max(0, bounds.top - 6) + "px";
    marker.style.left = Math.max(0, bounds.left - 6) + "px";
    pins.push(marker);
  }
  return pins;
}

function render(): void {
  const panel = open ? (
    <section className="panel" aria-label="preview feedback">
      <h2>Feedback</h2>
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
      <p>Leave feedback on this page. Select an element or report on the page.</p>
      <button
        type="button"
        onClick={() => {
          picking = true;
          error = "select an element on the page";
          render();
        }}
      >
        {pin.kind === "element" ? `Pinned: ${pin.label ?? "element"}` : "Pin an element"}
      </button>
      {pin.kind === "element" ? (
        <button
          type="button"
          onClick={() => {
            pin = { kind: "page" };
            render();
          }}
        >
          Use page instead
        </button>
      ) : null}
      <textarea
        aria-label="what happened"
        placeholder="What happened?"
        value={message}
        onInput={(event: Event) => {
          message = (event.target as HTMLTextAreaElement).value;
          reportKey = crypto.randomUUID();
        }}
      />
      <input
        type="text"
        aria-label="display name"
        placeholder="Name (optional, unverified)"
        value={displayName}
        onInput={(event: Event) => {
          displayName = (event.target as HTMLInputElement).value;
          reportKey = crypto.randomUUID();
        }}
      />
      <label>
        <input
          type="checkbox"
          checked={includeEvidence}
          onChange={(event: Event) => {
            includeEvidence = (event.target as HTMLInputElement).checked;
            reportKey = crypto.randomUUID();
            render();
          }}
        />{" "}
        Include actions and failed requests
      </label>
      <div className="evidence">
        {`Element: ${pin.html ?? "page"}\n`}
        {includeEvidence
          ? `Actions: ${actions.map((action) => action.type + " " + (action.label ?? action.path ?? "")).join("; ")}\nFailed requests: ${failures.map((failed) => `${failed.method} ${failed.path} ${failed.status} (${failed.duration_ms}ms)`).join("; ")}`
          : "No activity evidence will be included."}
      </div>
      <button
        type="button"
        className="primary"
        onClick={() => {
          void submit();
        }}
      >
        Submit feedback
      </button>
      <h2>Feedback list</h2>
      {threads.length === 0 ? (
        <p>No feedback on this page yet.</p>
      ) : (
        threads.map((thread) => (
          <div className="thread">
            <button
              type="button"
              onClick={() => {
                void openThread(thread);
              }}
            >
              {thread.report.text.slice(0, 140)}
            </button>
            <span>{thread.state.replaceAll("_", " ")}</span>
          </div>
        ))
      )}
      {nextThreadCursor ? (
        <button
          type="button"
          onClick={() => {
            void loadMoreThreads();
          }}
        >
          Load more feedback
        </button>
      ) : null}
      {selectedThread ? (
        <section className="thread" aria-label="feedback thread">
          <h2>{selectedThread.report.text}</h2>
          <p>
            {selectedThread.element.label ?? "Page-level feedback"} ·{" "}
            {selectedThread.state.replaceAll("_", " ")}
          </p>
          {events.map((event) => (
            <p className="detail">
              {event.type}: {event.text ?? ""}
            </p>
          ))}
          {nextEventCursor !== undefined ? (
            <button
              type="button"
              onClick={() => {
                void loadMoreEvents();
              }}
            >
              Load more events
            </button>
          ) : null}
          {selectedThread.state !== "resolved" ? (
            <textarea
              aria-label="reply"
              placeholder="Reply or describe your fix"
              value={reply}
              onInput={(event: Event) => {
                reply = (event.target as HTMLTextAreaElement).value;
                eventKey = crypto.randomUUID();
              }}
            />
          ) : null}
          {selectedThread.state !== "resolved" ? (
            <button
              type="button"
              onClick={() => {
                void sendEvent("reply");
              }}
            >
              Reply
            </button>
          ) : null}
          {owner && selectedThread.state === "open" ? (
            <button
              type="button"
              onClick={() => {
                void sendEvent("fix.ready_for_recheck");
              }}
            >
              Ready for recheck
            </button>
          ) : null}
          {owner && selectedThread.state === "ready_for_recheck" ? (
            <button
              type="button"
              onClick={() => {
                void sendEvent("thread.resolved");
              }}
            >
              Resolve
            </button>
          ) : null}
          {!owner && selectedThread.state === "ready_for_recheck" ? (
            <button
              type="button"
              onClick={() => {
                void sendEvent("recheck.still_broken");
              }}
            >
              Still broken
            </button>
          ) : null}
        </section>
      ) : null}
    </section>
  ) : null;
  shadow.replaceChildren(
    styles,
    ...renderPins(),
    <button
      type="button"
      className="toggle"
      onClick={() => {
        open = !open;
        if (open) void refresh();
        else render();
      }}
      aria-label="feedback toolbar"
    >
      Feedback
    </button>,
    ...(panel ? [panel] : []),
  );
}

document.addEventListener(
  "click",
  (event) => {
    const element = event.target;
    if (!(element instanceof Element) || root.contains(element)) return;
    if (picking) {
      picking = false;
      pin = requestPin(element);
      reportKey = crypto.randomUUID();
      error = "";
      event.preventDefault();
      event.stopImmediatePropagation();
      render();
      return;
    }
    pushAction({
      type: "click",
      label: label(element),
      test_id: element.getAttribute("data-testid") ?? undefined,
    });
  },
  true,
);
document.addEventListener(
  "submit",
  (event) => {
    if (event.target instanceof Element && !root.contains(event.target))
      pushAction({ type: "submit", label: label(event.target) });
  },
  true,
);
window.addEventListener("popstate", () => {
  pushAction({ type: "navigation", path: location.pathname });
  void refresh();
});
window.addEventListener(
  "scroll",
  () => {
    if (open) render();
  },
  { passive: true },
);
window.addEventListener("resize", () => {
  if (open) render();
});
render();
