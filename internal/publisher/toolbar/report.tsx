import { useRef, useState } from "preact/hooks";
import { useMutation, useQuery } from "@tanstack/react-query";
import type { FeedbackAPI } from "./api.ts";
import { mutationKey } from "./async.ts";
import { useViewSignal } from "./queries.ts";
import type { AnchorTarget } from "./anchors.ts";
import { boundedText } from "./evidence.ts";
import { EvidenceView } from "./evidence-view.tsx";
import { FeedbackSignIn } from "./sign-in.tsx";
import type { Action, Evidence, ReportInput, Thread } from "./model.ts";

export function ReportForm({
  api,
  path,
  document,
  actions,
  target,
  saved,
  cancel,
  signedIn,
  browserName,
}: {
  api: FeedbackAPI;
  path: string;
  document: Document;
  actions: () => Action[];
  target?: AnchorTarget | undefined;
  saved: (thread: Thread) => void;
  cancel: () => void;
  signedIn: boolean;
  browserName?: string | undefined;
}) {
  const [text, setText] = useState("");
  const [includeActivity, setIncludeActivity] = useState(false);
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
      if (new TextEncoder().encode(input.text).length > 4000)
        throw new FeedbackError("text_too_long");
      return api.report(input, key.current(input), signal);
    },
    onSuccess: (thread) => {
      if (!signal.aborted) saved(thread);
    },
  });
  function submit(): void {
    if (!signedIn) return;
    send.mutate({
      schema_version: 1,
      text: text.trim(),
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
      {send.error && <p role="alert">{safeFeedbackMessage(send.error)}</p>}
      <FeedbackSignIn error={send.error} path={path} required={!signedIn} />
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
              onInput={(event) => setText(event.currentTarget.value)}
            />
          </label>
          {signedIn && browserName && <small>posting as {browserName}</small>}
          <EvidenceView evidence={evidence} />
          <label class="activity-choice">
            <input
              type="checkbox"
              checked={includeActivity}
              onChange={(event) => setIncludeActivity(event.currentTarget.checked)}
            />
            Include activity
          </label>
          {includeActivity && (
            <small>
              Review context before sharing. Labels and paths may contain sensitive text.
            </small>
          )}
          {includeActivity && failures.isPending && <small>loading request context…</small>}
          {includeActivity && failures.error && (
            <small>request context unavailable; omit activity to send</small>
          )}
          <div class="composer-actions">
            <button type="button" onClick={cancel}>
              cancel
            </button>
            <button
              type="submit"
              disabled={
                !signedIn ||
                !text.trim() ||
                (includeActivity && (failures.isPending || failures.isError))
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
