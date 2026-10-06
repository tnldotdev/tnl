import { useRef, useState } from "preact/hooks";
import { useMutation, useQuery } from "@tanstack/react-query";
import type { FeedbackAPI } from "./api.ts";
import { mutationKey } from "./async.ts";
import { useViewSignal } from "./queries.ts";
import type { AnchorTarget } from "./anchors.ts";
import { boundedText } from "./evidence.ts";
import { EvidenceView } from "./evidence-view.tsx";
import type { Action, Evidence, ReportInput, Thread } from "./model.ts";

export function ReportForm({
  api,
  path,
  document,
  actions,
  target,
  saved,
  cancel,
  browserName,
}: {
  api: FeedbackAPI;
  path: string;
  document: Document;
  actions: () => Action[];
  target?: AnchorTarget | undefined;
  saved: (thread: Thread) => void;
  cancel: () => void;
  browserName?: string | undefined;
}) {
  const [text, setText] = useState("");
  const [name, setName] = useState("");
  const [includeActivity, setIncludeActivity] = useState(true);
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
        throw new Error("feedback must be at most 4000 bytes");
      if (new TextEncoder().encode(input.display_name).length > 64)
        throw new Error("the name must be at most 64 bytes");
      return api.report(input, key.current(input), signal);
    },
    onSuccess: (thread) => {
      if (!signal.aborted) saved(thread);
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
      {send.error && <p role="alert">{send.error.message}</p>}
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
          {browserName ? (
            <small>posting as {browserName}</small>
          ) : (
            <label class="display-name">
              Name (optional, unverified)
              <input
                maxLength={64}
                placeholder="name (optional)"
                value={name}
                onInput={(event) => setName(event.currentTarget.value)}
              />
            </label>
          )}
          <EvidenceView evidence={evidence} />
          <label class="activity-choice">
            <input
              type="checkbox"
              checked={includeActivity}
              onChange={(event) => setIncludeActivity(event.currentTarget.checked)}
            />
            Include activity
          </label>
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
                !text.trim() || (includeActivity && (failures.isPending || failures.isError))
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
