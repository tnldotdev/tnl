import { useEffect, useRef, useState } from "preact/hooks";
import type { FeedbackAPI } from "./api.ts";
import { mutationKey, useRequest } from "./async.ts";
import type { BrowserEvent, FeedbackEvent, Thread } from "./model.ts";
import { supportedAnchor } from "./anchors.ts";

const eventLabels = {
  "thread.created": "Reported",
  reply: "Reply",
  update: "Update",
  "thread.resolved": "Resolved",
  "thread.reopened": "Reopened",
};

export function ThreadView({
  api,
  id,
  changed,
  back,
}: {
  api: FeedbackAPI;
  id: string;
  changed: () => void;
  back: () => void;
}) {
  const [thread, setThread] = useState<Thread>();
  const [events, setEvents] = useState<FeedbackEvent[]>([]);
  const [cursor, setCursor] = useState<number>();
  const [text, setText] = useState("");
  const [pollError, setPollError] = useState("");
  const latestCursor = useRef(0);
  const ready = useRef(false);
  const mutationEpoch = useRef(0);
  const keys = useRef(mutationKey());
  const request = useRequest();
  async function load(): Promise<void> {
    await request.run(async (signal) => {
      const history = await api.events(id, undefined, signal);
      const value = await api.inspect(id, signal);
      if (signal.aborted) return;
      setThread(value);
      setEvents(history.events);
      setCursor(history.next_cursor);
      latestCursor.current = history.event_cursor;
      ready.current = true;
    });
  }
  useEffect(() => {
    void load();
  }, [id]);
  useEffect(() => {
    const controller = new AbortController();
    let polling = false;
    const timer = setInterval(() => {
      if (polling) return;
      polling = true;
      if (!ready.current) {
        void load().finally(() => {
          polling = false;
        });
        return;
      }
      const epoch = mutationEpoch.current;
      void (async () => {
        try {
          const page = await api.events(id, latestCursor.current, controller.signal);
          const current = await api.inspect(id, controller.signal);
          if (controller.signal.aborted) return;
          setEvents((previous) =>
            [
              ...previous,
              ...page.events.filter(
                (event) => !previous.some((entry) => entry.cursor === event.cursor),
              ),
            ].sort((left, right) => left.cursor - right.cursor),
          );
          latestCursor.current =
            page.next_cursor ??
            Math.max(page.event_cursor, ...page.events.map((event) => event.cursor));
          // a poll started before an action must not undo its optimistic state.
          if (epoch === mutationEpoch.current) setThread(current);
          setPollError("");
        } catch (reason) {
          if (!controller.signal.aborted)
            setPollError(
              reason instanceof Error ? reason.message : "could not load new replies; retrying",
            );
        } finally {
          polling = false;
        }
      })();
    }, 2000);
    return () => {
      clearInterval(timer);
      controller.abort();
    };
  }, [api, id]);
  async function append(type: BrowserEvent): Promise<void> {
    await request.run(async (signal) => {
      mutationEpoch.current++;
      const event = await api.append(
        id,
        type,
        text.trim(),
        keys.current({ id, type, text: text.trim() }),
        signal,
      );
      if (signal.aborted) return;
      mutationEpoch.current++;
      setText("");
      keys.current = mutationKey();
      setEvents((previous) =>
        [...previous.filter((entry) => entry.cursor !== event.cursor), event].sort(
          (left, right) => left.cursor - right.cursor,
        ),
      );
      setThread((previous) =>
        previous
          ? {
              ...previous,
              state:
                type === "thread.resolved"
                  ? "resolved"
                  : type === "thread.reopened"
                    ? "open"
                    : previous.state,
            }
          : previous,
      );
      changed();
    });
  }
  return (
    <section aria-label="Feedback thread">
      <button type="button" onClick={back}>
        Back to feedback
      </button>
      {request.error && <p role="alert">{request.error}</p>}
      {pollError && <p role="status">{pollError}; retrying automatically</p>}
      {!thread ? (
        <p role="status">{request.pending ? "Loading feedback…" : "Feedback is unavailable."}</p>
      ) : (
        <>
          <h2>{thread.report.text}</h2>
          <p>{thread.state === "open" ? "Open" : "Resolved"}</p>
          {supportedAnchor(thread.anchor)?.selection && (
            <blockquote>
              <small>quoted when posted</small>
              <p>{supportedAnchor(thread.anchor)?.selection?.text}</p>
            </blockquote>
          )}
          {thread.anchor && !supportedAnchor(thread.anchor) && (
            <p>this anchor format is not supported; the conversation is still available</p>
          )}
          <details>
            <summary>Original evidence</summary>
            <pre>
              {JSON.stringify({ anchor: thread.anchor, evidence: thread.evidence }, null, 2)}
            </pre>
          </details>
          <ol aria-label="History">
            {events.map((event) => (
              <li key={event.cursor}>
                <strong>{eventLabels[event.type]}</strong>{" "}
                <time dateTime={event.at}>{new Date(event.at).toLocaleString()}</time>
                {event.text && <p>{event.text}</p>}
              </li>
            ))}
          </ol>
          {cursor !== undefined && (
            <button
              type="button"
              disabled={request.pending}
              onClick={() => {
                void request.run(async (signal) => {
                  const page = await api.events(id, cursor, signal);
                  if (page.next_cursor !== undefined && page.next_cursor <= cursor)
                    throw new Error("the server repeated a history page; refresh the thread");
                  if (signal.aborted) return;
                  setEvents((previous) =>
                    [
                      ...previous,
                      ...page.events.filter(
                        (event) => !previous.some((entry) => entry.cursor === event.cursor),
                      ),
                    ].sort((left, right) => left.cursor - right.cursor),
                  );
                  setCursor(page.next_cursor);
                });
              }}
            >
              Load more history
            </button>
          )}
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void append("reply");
            }}
          >
            <label>
              {thread.state === "open" ? "Reply" : "Note (optional)"}
              <textarea
                disabled={request.pending}
                maxLength={4000}
                value={text}
                onInput={(event) => setText(event.currentTarget.value)}
              />
            </label>
            {thread.state === "open" && (
              <button type="submit" disabled={request.pending || !text.trim()}>
                Send reply
              </button>
            )}
            <button
              type="button"
              disabled={request.pending}
              onClick={() => {
                void append(thread.state === "open" ? "thread.resolved" : "thread.reopened");
              }}
            >
              {thread.state === "open" ? "Resolve" : "Reopen"}
            </button>
          </form>
        </>
      )}
    </section>
  );
}
