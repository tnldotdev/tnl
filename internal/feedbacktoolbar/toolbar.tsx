import { useEffect, useRef, useState } from "preact/hooks";
import type { FeedbackAPI } from "./api.ts";
import { useRequest } from "./async.ts";
import { observeActions } from "./evidence.ts";
import type { Action, Summary } from "./model.ts";
import { Pins } from "./pins.tsx";
import { ReportForm } from "./report.tsx";
import { ThreadView } from "./thread.tsx";
import { AsciiBar } from "./frame.tsx";

function FeedbackPage({
  api,
  path,
  document,
  host,
  actions,
}: {
  api: FeedbackAPI;
  path: string;
  document: Document;
  host: Element;
  actions: () => Action[];
}) {
  const [threads, setThreads] = useState<Summary[]>([]);
  const [cursor, setCursor] = useState<string>();
  const [selected, setSelected] = useState<string>();
  const request = useRequest();
  async function load(next?: string): Promise<void> {
    await request.run(async (signal) => {
      const page = await api.list(path, next, signal);
      if (signal.aborted) return;
      if (next && page.next_cursor === next)
        throw new Error("the server repeated a feedback page; refresh the list");
      setThreads((previous) =>
        next
          ? [
              ...previous,
              ...page.threads.filter((thread) => !previous.some((entry) => entry.id === thread.id)),
            ]
          : page.threads,
      );
      setCursor(page.next_cursor);
    });
  }
  useEffect(() => {
    void load();
  }, [path]);
  return (
    <>
      <Pins document={document} threads={threads} select={setSelected} />
      {selected ? (
        <ThreadView
          key={selected}
          api={api}
          id={selected}
          changed={() => {
            void load();
          }}
          back={() => {
            setSelected(undefined);
            void load();
          }}
        />
      ) : (
        <>
          <ReportForm
            api={api}
            path={path}
            document={document}
            host={host}
            actions={actions}
            saved={(id) => {
              setSelected(id);
              void load();
            }}
          />
          <section aria-label="Feedback list">
            <h2>Feedback list</h2>
            {request.error && <p role="alert">{request.error}</p>}
            <button
              type="button"
              disabled={request.pending}
              onClick={() => {
                void load();
              }}
            >
              Refresh feedback
            </button>
            {request.pending && <p role="status">Loading feedback…</p>}
            {!request.pending && !threads.length && !request.error && (
              <p>No feedback on this page yet.</p>
            )}
            <ul>
              {threads.map((thread) => (
                <li key={thread.id}>
                  <button
                    type="button"
                    class="comment-button"
                    onClick={() => setSelected(thread.id)}
                  >
                    {thread.report.text}
                  </button>{" "}
                  <span>{thread.state === "open" ? "Open" : "Resolved"}</span>
                </li>
              ))}
            </ul>
            {cursor && (
              <button
                type="button"
                disabled={request.pending}
                onClick={() => {
                  void load(cursor);
                }}
              >
                Load more feedback
              </button>
            )}
          </section>
        </>
      )}
    </>
  );
}

export function Toolbar({
  api,
  document,
  host,
}: {
  api: FeedbackAPI;
  document: Document;
  host: Element;
}) {
  const [open, setOpen] = useState(false);
  const [path, setPath] = useState(document.location.pathname + document.location.search);
  const actions = useRef<Action[]>([{ type: "navigation", path: document.location.pathname }]);
  const toggle = useRef<HTMLButtonElement>(null);
  useEffect(
    () =>
      observeActions(document, host, (action) => {
        actions.current = [...actions.current.slice(-19), action];
      }),
    [document, host],
  );
  useEffect(() => {
    const window = document.defaultView;
    if (!window) return;
    // polling catches pushState without replacing the app's History methods.
    const interval = window.setInterval(() => {
      const current = document.location.pathname + document.location.search;
      if (current !== path) {
        setPath(current);
        actions.current = [
          ...actions.current.slice(-19),
          { type: "navigation", path: document.location.pathname },
        ];
      }
    }, 500);
    return () => window.clearInterval(interval);
  }, [document, path]);
  useEffect(() => {
    if (!open) return;
    function key(event: Event): void {
      if (event instanceof KeyboardEvent && event.key === "Escape") {
        setOpen(false);
        toggle.current?.focus();
      }
    }
    host.addEventListener("keydown", key);
    return () => host.removeEventListener("keydown", key);
  }, [open, host]);
  return (
    <>
      <button
        ref={toggle}
        type="button"
        class="toggle"
        aria-expanded={open}
        aria-controls="tnl-feedback-panel"
        aria-label="Feedback"
        onClick={() => setOpen(!open)}
      >
        [ tnl feedback ]
      </button>
      {open && (
        <aside id="tnl-feedback-panel" class="panel" aria-label="Preview feedback">
          <AsciiBar
            title="tnl feedback"
            close={() => {
              setOpen(false);
              toggle.current?.focus();
            }}
          />
          <div class="panel-body">
            <FeedbackPage
              key={path}
              api={api}
              path={path}
              document={document}
              host={host}
              actions={() => actions.current}
            />
          </div>
          <AsciiBar />
        </aside>
      )}
    </>
  );
}
