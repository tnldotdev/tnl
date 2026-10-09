import { useRef, useState } from "preact/hooks";
import { useMutation, useQuery } from "@tanstack/react-query";
import type { FeedbackAPI } from "./api.ts";
import { mutationKey } from "./async.ts";
import { useViewSignal } from "./queries.ts";
import type { AnchorTarget } from "./anchors.ts";
import { boundedText } from "./evidence.ts";
import { EvidenceView } from "./evidence-view.tsx";
import type { Action, Evidence, ReportInput, Thread } from "./model.ts";
import { authorKey, canPost, PostingIdentity, type Posting } from "./access.tsx";

export function ReportForm({
  api,
  path,
  document,
  actions,
  target,
  saved,
  cancel,
  posting,
}: {
  api: FeedbackAPI;
  path: string;
  document: Document;
  actions: () => Action[];
  target?: AnchorTarget | undefined;
  saved: (thread: Thread) => void;
  cancel: () => void;
  posting: Posting;
}) {
  const [text, setText] = useState("");
  const [name, setName] = useState("");
  const [includeActivity, setIncludeActivity] = useState(true);
  const [attempt, setAttempt] = useState<{ input: ReportInput; key: string; author: string }>();
  const frozen = useRef<typeof attempt>(undefined);
  const uncertain = useRef(false);
  const latest = useRef(posting);
  latest.current = posting;
  const browserName = posting.access?.identity?.display_name;
  const authorChanged =
    !!posting.access && !!attempt && attempt.author !== authorKey(posting.access);
  const [activity] = useState(() => actions().slice(-20));
  const [draftKey] = useState(() => crypto.randomUUID());
  const key = useRef(mutationKey());
  const signal = useViewSignal();
  const failures = useQuery({
    queryKey: ["draft-context", draftKey],
    queryFn: ({ signal }) => api.evidence(signal),
    enabled: includeActivity,
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  });
  const evidence: Evidence = {
    schema_version: 1,
    ...(target?.element ? { element: target.element } : {}),
    actions: includeActivity ? activity : [],
    failed_requests: includeActivity ? (failures.data ?? []) : [],
  };
  const send = useMutation({
    mutationFn: async (input: ReportInput) => {
      const currentPosting = latest.current;
      if (!canPost(currentPosting.access)) throw new FeedbackError("sign_in_required");
      if (new TextEncoder().encode(input.text).length > 4000)
        throw new FeedbackError("text_too_long");
      if (new TextEncoder().encode(input.display_name).length > 64)
        throw new FeedbackError("name_too_long");
      const author = frozen.current?.author ?? authorKey(currentPosting.access);
      await currentPosting.authorize(author);
      if (!frozen.current) {
        const prepared = { ...input, posting_identity: author };
        frozen.current = { input: prepared, key: key.current(prepared), author };
        setAttempt(frozen.current);
      }
      return api.report(frozen.current.input, frozen.current.key, signal);
    },
    onSuccess: (thread) => {
      if (!signal.aborted) saved(thread);
    },
    onError: (error) => {
      if (
        error instanceof FeedbackError &&
        ["sign_in_required", "access_expired", "input_invalid"].includes(error.code) &&
        !uncertain.current
      ) {
        frozen.current = undefined;
        setAttempt(undefined);
      } else if (frozen.current) {
        uncertain.current = true;
      }
      posting.refresh();
    },
  });
  function submit(): void {
    send.mutate({
      schema_version: 1,
      text: text.trim(),
      display_name: browserName ? "" : name.trim(),
      page_path: path,
      page_title: boundedText(document.title, 256),
      ...(target ? { anchor: target.anchor } : {}),
      evidence,
    });
  }
  return (
    <section aria-label="New feedback">
      {target?.anchor.selection && (
        <blockquote>
          <p>{target.anchor.selection.text}</p>
        </blockquote>
      )}
      {!target && <small>on this page</small>}
      <PostingIdentity posting={posting} />
      {authorChanged && (
        <p role="status">
          the previous attempt used another posting identity. check the feedback list before editing
          the draft.
        </p>
      )}
      {attempt && send.error && uncertain.current && (
        <p role="status">this may have been sent; check the feedback list before editing.</p>
      )}
      {send.error && <p role="alert">{safeFeedbackMessage(send.error)}</p>}
      <form
        onSubmit={(event) => {
          event.preventDefault();
          submit();
        }}
      >
        <fieldset disabled={send.isPending}>
          <label>
            <span class="sr-only">Feedback</span>
            <textarea
              autoFocus
              required
              maxLength={4000}
              placeholder="Leave feedback…"
              value={text}
              readOnly={!!attempt}
              onInput={(event) => setText(event.currentTarget.value)}
            />
          </label>
          {!browserName &&
            posting.access?.identity_state === "anonymous" &&
            !posting.access.require_sign_in && (
              <label class="display-name">
                Name (optional, unverified)
                <input
                  maxLength={64}
                  placeholder="name (optional)"
                  value={name}
                  readOnly={!!attempt}
                  onInput={(event) => setName(event.currentTarget.value)}
                />
              </label>
            )}
          <EvidenceView evidence={attempt?.input.evidence ?? evidence} />
          <label class="activity-choice">
            <input
              type="checkbox"
              checked={includeActivity}
              disabled={!!attempt}
              onChange={(event) => setIncludeActivity(event.currentTarget.checked)}
            />
            Include activity
          </label>
          {includeActivity && failures.isPending && <small>loading request context…</small>}
          {includeActivity && failures.error && (
            <small>request context unavailable; omit activity to send</small>
          )}
          <div class="composer-actions">
            {attempt && !send.isPending && (
              <button
                type="button"
                onClick={() => {
                  frozen.current = undefined;
                  uncertain.current = false;
                  setAttempt(undefined);
                  key.current = mutationKey();
                }}
              >
                edit draft
              </button>
            )}
            <button type="button" onClick={cancel}>
              cancel
            </button>
            <button
              type="submit"
              disabled={
                !canPost(posting.access) ||
                authorChanged ||
                !text.trim() ||
                (!attempt && includeActivity && (failures.isPending || failures.isError))
              }
            >
              {send.isPending ? "sending…" : "send feedback"}
            </button>
          </div>
        </fieldset>
      </form>
    </section>
  );
}
import { FeedbackError, safeFeedbackMessage } from "./errors.ts";
