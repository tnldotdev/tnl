import { useRef, useState } from "preact/hooks";
import type { FeedbackAPI } from "./api.ts";
import { mutationKey } from "./async.ts";
import type { BrowserEvent } from "./model.ts";
import { supportedAnchor } from "./anchors.ts";
import { useConversation } from "./queries.ts";
import { EvidenceView } from "./evidence-view.tsx";
import { authorKey, canPost, PostingIdentity, type Posting } from "./access.tsx";
import { FeedbackError } from "./errors.ts";

const eventLabels = {
  "thread.created": "reported",
  reply: "reply",
  update: "update",
  "thread.resolved": "resolved",
  "thread.reopened": "reopened",
};

export function ThreadView({
  api,
  id,
  posting,
}: {
  api: FeedbackAPI;
  id: string;
  posting: Posting;
}) {
  const [text, setText] = useState("");
  const [attempt, setAttempt] = useState<{
    type: BrowserEvent;
    text: string;
    key: string;
    author: string;
  }>();
  const keys = useRef(mutationKey());
  const uncertain = useRef(false);
  const { query, append, history } = useConversation(api, id, async (author) => {
    if (!canPost(posting.access)) throw new FeedbackError("sign_in_required");
    await posting.authorize(author);
  });
  const data = query.data;
  const error = append.error ?? history.error ?? query.error;
  const anchor = supportedAnchor(data?.thread.anchor);
  const authorChanged =
    !!posting.access && !!attempt && attempt.author !== authorKey(posting.access);
  function send(type: BrowserEvent): void {
    if (!canPost(posting.access) || (attempt && attempt.type !== type)) return;
    const current = attempt ?? {
      type,
      text: text.trim(),
      key: keys.current({ id, type, text: text.trim() }),
      author: authorKey(posting.access),
    };
    setAttempt(current);
    append.mutate(current, {
      onSuccess: () => {
        setText("");
        keys.current = mutationKey();
        setAttempt(undefined);
        uncertain.current = false;
      },
      onError: (error) => {
        if (
          error instanceof FeedbackError &&
          ["sign_in_required", "access_expired", "input_invalid"].includes(error.code) &&
          !uncertain.current
        )
          setAttempt(undefined);
        else uncertain.current = true;
        posting.refresh();
      },
    });
  }
  return (
    <section aria-label="Feedback thread">
      {error && <p role="status">{safeFeedbackMessage(error)}</p>}
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
            <PostingIdentity posting={posting} />
            {authorChanged && (
              <p role="status">
                the previous attempt used another posting identity. check the history before editing
                the draft.
              </p>
            )}
            {attempt && append.error && uncertain.current && (
              <p role="status">this may have been sent; check the history before editing.</p>
            )}
            <label>
              {data.thread.state === "open" ? "Reply" : "Note (optional)"}
              <textarea
                disabled={append.isPending}
                readOnly={!!attempt}
                maxLength={4000}
                value={text}
                onInput={(event) => setText(event.currentTarget.value)}
              />
            </label>
            {data.thread.state === "open" && (
              <button
                type="submit"
                disabled={
                  !canPost(posting.access) ||
                  authorChanged ||
                  append.isPending ||
                  !text.trim() ||
                  (!!attempt && attempt.type !== "reply")
                }
              >
                Send reply
              </button>
            )}
            <button
              type="button"
              disabled={
                !canPost(posting.access) ||
                authorChanged ||
                append.isPending ||
                (!!attempt &&
                  attempt.type !==
                    (data.thread.state === "open" ? "thread.resolved" : "thread.reopened"))
              }
              onClick={() =>
                send(data.thread.state === "open" ? "thread.resolved" : "thread.reopened")
              }
            >
              {data.thread.state === "open" ? "Resolve" : "Reopen"}
            </button>
            {attempt && !append.isPending && (
              <button
                type="button"
                onClick={() => {
                  setAttempt(undefined);
                  uncertain.current = false;
                  keys.current = mutationKey();
                }}
              >
                edit draft
              </button>
            )}
          </form>
        </>
      )}
    </section>
  );
}
import { safeFeedbackMessage } from "./errors.ts";
