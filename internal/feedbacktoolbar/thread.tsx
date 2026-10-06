import { useRef, useState } from "preact/hooks";
import type { FeedbackAPI } from "./api.ts";
import { mutationKey } from "./async.ts";
import type { BrowserEvent } from "./model.ts";
import { supportedAnchor } from "./anchors.ts";
import { useConversation } from "./queries.ts";
import { EvidenceView } from "./evidence-view.tsx";

const eventLabels = {
  "thread.created": "reported",
  reply: "reply",
  update: "update",
  "thread.resolved": "resolved",
  "thread.reopened": "reopened",
};

export function ThreadView({ api, id }: { api: FeedbackAPI; id: string }) {
  const [text, setText] = useState("");
  const keys = useRef(mutationKey());
  const { query, append, history } = useConversation(api, id);
  const data = query.data;
  const error = append.error ?? history.error ?? query.error;
  const anchor = supportedAnchor(data?.thread.anchor);
  function send(type: BrowserEvent): void {
    append.mutate(
      { type, text: text.trim(), key: keys.current({ id, type, text: text.trim() }) },
      {
        onSuccess: () => {
          setText("");
          keys.current = mutationKey();
        },
      },
    );
  }
  return (
    <section aria-label="Feedback thread">
      {error && <p role="status">{error.message}</p>}
      {!data ? (
        <p role="status">{query.isPending ? "Loading feedback…" : "Feedback is unavailable."}</p>
      ) : (
        <>
          <div class="comment-meta">
            <span>
              {data.thread.report.author?.display_name ?? "anonymous"}
              {data.thread.report.author && !data.thread.report.author.verified && (
                <small> · unverified</small>
              )}
            </span>
            <time dateTime={data.thread.report.created_at}>
              {new Date(data.thread.report.created_at).toLocaleString()}
            </time>
          </div>
          <h2>{data.thread.report.text}</h2>
          <p>{data.thread.state}</p>
          {anchor?.selection && (
            <blockquote>
              <small>quoted when posted</small>
              <p>{anchor.selection.text}</p>
            </blockquote>
          )}
          {data.thread.anchor && !anchor && (
            <p>this anchor format is not supported; the conversation is still available</p>
          )}
          <EvidenceView evidence={data.thread.evidence} />
          <ol aria-label="History">
            {data.events.map((event) => (
              <li key={event.cursor}>
                <strong>{eventLabels[event.type]}</strong>{" "}
                {event.author && (
                  <span class="muted">
                    by {event.author.display_name}
                    {!event.author.verified && " (unverified)"}{" "}
                  </span>
                )}
                <time dateTime={event.at}>{new Date(event.at).toLocaleString()}</time>
                {event.text && <p>{event.text}</p>}
              </li>
            ))}
          </ol>
          {data.olderCursor !== undefined && (
            <button
              type="button"
              disabled={history.isPending || append.isPending}
              onClick={() => history.mutate(data.olderCursor ?? 0)}
            >
              Load more history
            </button>
          )}
          <form
            onSubmit={(event) => {
              event.preventDefault();
              send("reply");
            }}
          >
            <label>
              {data.thread.state === "open" ? "Reply" : "Note (optional)"}
              <textarea
                disabled={append.isPending}
                maxLength={4000}
                value={text}
                onInput={(event) => setText(event.currentTarget.value)}
              />
            </label>
            {data.thread.state === "open" && (
              <button type="submit" disabled={append.isPending || !text.trim()}>
                Send reply
              </button>
            )}
            <button
              type="button"
              disabled={append.isPending}
              onClick={() =>
                send(data.thread.state === "open" ? "thread.resolved" : "thread.reopened")
              }
            >
              {data.thread.state === "open" ? "Resolve" : "Reopen"}
            </button>
          </form>
        </>
      )}
    </section>
  );
}
