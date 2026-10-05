import { useEffect, useRef, useState } from "preact/hooks";
import type { FeedbackAPI } from "./api.ts";
import { mutationKey, useRequest } from "./async.ts";
import { beginPicking, captureSelection, type AnchorTarget } from "./anchors.ts";
import type { Action, Evidence, ReportInput } from "./model.ts";

export function ReportForm({
  api,
  path,
  actions,
  document,
  host,
  saved,
}: {
  api: FeedbackAPI;
  path: string;
  actions: () => Action[];
  document: Document;
  host: Element;
  saved: (id: string) => void;
}) {
  const [text, setText] = useState("");
  const [name, setName] = useState("");
  const [target, setTarget] = useState<AnchorTarget>();
  const [picking, setPicking] = useState(false);
  const [includeEvidence, setIncludeEvidence] = useState(true);
  const [preview, setPreview] = useState<ReportInput>();
  const key = useRef(mutationKey());
  const request = useRequest();
  useEffect(
    () =>
      picking
        ? beginPicking(
            document,
            host,
            (selected) => {
              setTarget(selected);
              setPicking(false);
            },
            () => setPicking(false),
          )
        : undefined,
    [picking, document, host],
  );

  async function review(): Promise<void> {
    await request.run(async (signal) => {
      if (new TextEncoder().encode(text.trim()).length > 4000)
        throw new Error("feedback must be at most 4000 bytes");
      if (new TextEncoder().encode(name.trim()).length > 64)
        throw new Error("the name must be at most 64 bytes");
      const evidence: Evidence = includeEvidence
        ? {
            schema_version: 1,
            actions: actions().slice(-20),
            failed_requests: await api.evidence(signal),
          }
        : { schema_version: 1, actions: [], failed_requests: [] };
      if (target?.element) evidence.element = target.element;
      if (signal.aborted) return;
      setPreview({
        schema_version: 1,
        text: text.trim(),
        display_name: name.trim(),
        page_path: path,
        ...(target ? { anchor: target.anchor } : {}),
        evidence,
      });
    });
  }
  async function submit(): Promise<void> {
    if (!preview) return;
    await request.run(async (signal) => {
      const thread = await api.report(preview, key.current(preview), signal);
      if (signal.aborted) return;
      setText("");
      setTarget(undefined);
      setPreview(undefined);
      key.current = mutationKey();
      saved(thread.id);
    });
  }
  return (
    <section aria-label="New feedback">
      <h2>Leave feedback</h2>
      {request.error && <p role="alert">{request.error}</p>}
      {preview ? (
        <>
          <p>{preview.text}</p>
          <details open>
            <summary>Evidence to send</summary>
            <pre>
              {JSON.stringify({ anchor: preview.anchor, evidence: preview.evidence }, null, 2)}
            </pre>
          </details>
          <button type="button" disabled={request.pending} onClick={() => setPreview(undefined)}>
            Edit feedback
          </button>
          <button
            type="button"
            disabled={request.pending}
            onClick={() => {
              void submit();
            }}
          >
            {request.pending ? "Sending…" : "Send feedback"}
          </button>
        </>
      ) : (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void review();
          }}
        >
          <fieldset disabled={request.pending}>
            <label>
              Feedback
              <textarea
                required
                maxLength={4000}
                value={text}
                onInput={(event) => setText(event.currentTarget.value)}
              />
            </label>
            <label>
              Name (optional, unverified)
              <input
                maxLength={64}
                value={name}
                onInput={(event) => setName(event.currentTarget.value)}
              />
            </label>
            <p>
              {!target
                ? "Feedback on this page"
                : "Pinned: " + (target.element.label || target.element.role)}
            </p>
            <button type="button" onClick={() => setPicking(!picking)}>
              {picking ? "Cancel selection" : "Select an element"}
            </button>
            <button
              type="button"
              onMouseDown={(event) => event.preventDefault()}
              onClick={() => {
                const selected = captureSelection(document);
                if (selected) setTarget(selected);
              }}
            >
              Use selected text
            </button>
            {target && (
              <button type="button" onClick={() => setTarget(undefined)}>
                Use page instead
              </button>
            )}
            {picking && (
              <p role="status">Select an element on the page, or press Escape to cancel.</p>
            )}
            <label>
              <input
                type="checkbox"
                checked={includeEvidence}
                onChange={(event) => setIncludeEvidence(event.currentTarget.checked)}
              />
              Include recent actions and failed requests
            </label>
            <button type="submit" disabled={!text.trim()}>
              Review feedback
            </button>
          </fieldset>
        </form>
      )}
    </section>
  );
}
