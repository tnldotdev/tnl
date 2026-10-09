import { useEffect, useRef, useState } from "preact/hooks";
import {
  QueryClient,
  QueryClientProvider,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { usePageFeedback } from "./queries.ts";
import { observeActions } from "./evidence.ts";
import type { Action, Summary } from "./model.ts";
import { supportedAnchor, restoreAnchor, type AnchorTarget } from "./anchors.ts";
import { Pins } from "./pins.tsx";
import { ReportForm } from "./report.tsx";
import { ThreadView } from "./thread.tsx";
import { AsciiBar } from "./frame.tsx";
import { Popover } from "./popover.tsx";
import { Placement, SelectionHint } from "./placement.tsx";
import { FeedbackList, type ListFilters } from "./list.tsx";
import type { FeedbackAPI } from "./api.ts";
import { FeedbackError, safeFeedbackMessage } from "./errors.ts";
import { checkPosting, SignInLink, type Posting } from "./access.tsx";
import {
  recoverTarget,
  restoreDraft,
  saveDraft,
  type Recovery,
  type ReportDraft,
  type ThreadDraft,
} from "./drafts.ts";

type Draft = {
  path: string;
  target?: AnchorTarget | undefined;
  key: string;
  recovered?: ReportDraft | undefined;
};
type Selected = { thread: Summary; threads: Summary[]; recovered?: ThreadDraft | undefined };

function FeedbackLayer({
  api,
  document,
  host,
}: {
  api: FeedbackAPI;
  document: Document;
  host: Element;
}) {
  const [path, setPath] = useState(document.location.pathname + document.location.search);
  const [recovered] = useState(() => restoreDraft(document));
  const [placing, setPlacing] = useState(false);
  const [draft, setDraft] = useState<Draft | undefined>(() =>
    recovered?.mode === "report"
      ? {
          path,
          key: crypto.randomUUID(),
          target: recoverTarget(document, recovered.anchor),
          recovered,
        }
      : undefined,
  );
  const [selected, setSelected] = useState<Selected>();
  const [listOpen, setListOpen] = useState(false);
  const [filters, setFilters] = useState<ListFilters>({ pages: "current", state: "open" });
  const actions = useRef<Action[]>([{ type: "navigation", path: document.location.pathname }]);
  const toolbar = useRef<HTMLDivElement>(null);
  const client = useQueryClient();
  const unsent = useRef<Recovery | undefined>(recovered);
  const restoredOnce = useRef(false);
  const [recoveryError, setRecoveryError] = useState(false);
  const access = useQuery({
    queryKey: ["feedback-access"],
    queryFn: ({ signal }) => api.access(signal),
    retry: false,
    refetchInterval: 2000,
  });
  const signOut = useMutation({
    mutationFn: () => api.signOut(new AbortController().signal),
    onSuccess: () => client.invalidateQueries({ queryKey: ["feedback-access"] }),
  });
  const restoredThread = useQuery({
    queryKey: ["feedback-restore-thread", recovered?.mode === "thread" ? recovered.id : ""],
    queryFn: ({ signal }) =>
      recovered?.mode === "thread"
        ? api.inspect(recovered.id, signal)
        : Promise.reject(new FeedbackError("not_found")),
    enabled: recovered?.mode === "thread" && !restoredOnce.current,
    retry: false,
  });
  useEffect(() => {
    if (!restoredOnce.current && restoredThread.data && recovered?.mode === "thread") {
      restoredOnce.current = true;
      setSelected({ thread: restoredThread.data, threads: [restoredThread.data], recovered });
    }
  }, [restoredThread.data, recovered]);
  const posting: Posting = {
    access: access.isError || signOut.isPending ? undefined : access.data,
    error: access.error,
    path,
    refresh: () => {
      void client.invalidateQueries({ queryKey: ["feedback-access"] });
    },
    authorize: async (author) => {
      const current = await client.fetchQuery({
        queryKey: ["feedback-access"],
        queryFn: ({ signal }) => api.access(signal),
        staleTime: 0,
      });
      checkPosting(current, author);
    },
    signIn: (event) => {
      if (unsent.current && !saveDraft(document, unsent.current)) {
        event.preventDefault();
        setRecoveryError(true);
      }
    },
  };
  function remember(value: Recovery | undefined): void {
    unsent.current = value;
    saveDraft(document, value);
  }
  const query = usePageFeedback(api, path);
  const threads = [
    ...new Map(
      (query.data?.pages.flatMap((page) => page.threads) ?? []).map((thread) => [
        thread.id,
        thread,
      ]),
    ).values(),
  ];
  const current = selected
    ? (threads.find((thread) => thread.id === selected.thread.id) ?? selected.thread)
    : undefined;
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
    const timer = window.setInterval(() => {
      const next = document.location.pathname + document.location.search;
      if (next !== path) {
        setPath(next);
        restoredOnce.current = true;
        setDraft(undefined);
        setSelected(undefined);
        setPlacing(false);
        remember(undefined);
        actions.current = [
          ...actions.current.slice(-19),
          { type: "navigation", path: document.location.pathname },
        ];
      }
    }, 500);
    return () => window.clearInterval(timer);
  }, [document, path]);
  function newDraft(target?: AnchorTarget): void {
    restoredOnce.current = true;
    setPlacing(false);
    setListOpen(false);
    setSelected(undefined);
    remember(undefined);
    setDraft({ path, target, key: crypto.randomUUID() });
  }
  function select(thread: Summary, choices: Summary[]): void {
    restoredOnce.current = true;
    setSelected({ thread, threads: choices });
    setDraft(undefined);
    setListOpen(false);
    setPlacing(false);
    remember(undefined);
    if (thread.scope.page_path === path) {
      const anchor = supportedAnchor(thread.anchor);
      const element = anchor ? restoreAnchor(document, anchor)?.element : undefined;
      if (element instanceof HTMLElement) element.scrollIntoView?.({ block: "nearest" });
    }
  }
  const anchor = current?.scope.page_path === path ? supportedAnchor(current.anchor) : undefined;
  const missing = !!anchor && !restoreAnchor(document, anchor);
  const fallback = toolbar.current ?? host;
  return (
    <>
      <div ref={toolbar} class="toolbar" role="toolbar" aria-label="Feedback controls">
        {posting.access?.identity_state === "signed_in" && posting.access.identity ? (
          <>
            <span class="muted">signed in as {posting.access.identity.display_name}</span>
            <button type="button" disabled={signOut.isPending} onClick={() => signOut.mutate()}>
              [ sign out ]
            </button>
          </>
        ) : posting.access?.sign_in_available ? (
          <SignInLink posting={posting} />
        ) : null}
        {posting.access?.identity_state === "expired" && (
          <small>sign-in expired; your draft is still here</small>
        )}
        {access.error && <small role="status">{safeFeedbackMessage(access.error)}</small>}
        {recoveryError && (
          <small role="alert">could not preserve the draft; copy your text before signing in</small>
        )}
        {restoredThread.error && (
          <small role="status">{safeFeedbackMessage(restoredThread.error)}</small>
        )}
        {signOut.error && <small role="status">{safeFeedbackMessage(signOut.error)}</small>}
        <button
          type="button"
          aria-label="Comment"
          disabled={!!draft}
          aria-pressed={placing}
          onClick={() => {
            setPlacing(!placing);
            setSelected(undefined);
            setListOpen(false);
          }}
        >
          {placing ? "[ cancel ]" : "[ comment ]"}
        </button>
        {placing && (
          <button type="button" onClick={() => newDraft()}>
            on this page
          </button>
        )}
        <button
          type="button"
          aria-label="Feedback"
          aria-expanded={listOpen}
          onClick={() => {
            setListOpen(!listOpen);
            setSelected(undefined);
            setPlacing(false);
          }}
        >
          [ feedback{threads.length ? ` ${threads.length}` : ""} ]
        </button>
      </div>
      <Pins
        document={document}
        threads={
          current?.scope.page_path === path && !threads.some((thread) => thread.id === current.id)
            ? [...threads, current]
            : threads
        }
        selectedId={current?.id}
        select={(id) => {
          const thread = threads.find((thread) => thread.id === id) ?? current;
          if (thread) select(thread, threads);
        }}
      />
      {placing && <Placement document={document} host={host} picked={newDraft} />}
      {!draft && !selected && <SelectionHint document={document} picked={newDraft} />}
      {draft && (
        <Popover
          document={document}
          anchor={draft.target?.anchor}
          fallback={fallback}
          title="new feedback"
          close={() => {
            setDraft(undefined);
            remember(undefined);
          }}
        >
          <ReportForm
            key={draft.key}
            api={api}
            path={draft.path}
            document={document}
            actions={() => actions.current}
            target={draft.target}
            posting={posting}
            recovered={draft.recovered}
            changed={remember}
            cancel={() => {
              setDraft(undefined);
              remember(undefined);
            }}
            saved={(thread) => {
              setDraft(undefined);
              remember(undefined);
              void client.invalidateQueries({ queryKey: ["feedback-page"] });
              select(thread, [thread]);
            }}
          />
        </Popover>
      )}
      {current && (
        <Popover
          document={document}
          anchor={anchor}
          fallback={fallback}
          title="feedback"
          close={() => {
            setSelected(undefined);
            remember(undefined);
          }}
        >
          <div class="thread-navigation">
            <button
              type="button"
              onClick={() => {
                setSelected(undefined);
                setListOpen(true);
              }}
            >
              back to list
            </button>
            {selected && selected.threads.length > 1 && (
              <>
                <button
                  type="button"
                  aria-label="Previous feedback"
                  disabled={selected.threads.findIndex((thread) => thread.id === current.id) <= 0}
                  onClick={() => {
                    const next =
                      selected.threads[
                        selected.threads.findIndex((thread) => thread.id === current.id) - 1
                      ];
                    if (next) select(next, selected.threads);
                  }}
                >
                  [ ^ ]
                </button>
                <button
                  type="button"
                  aria-label="Next feedback"
                  disabled={
                    selected.threads.findIndex((thread) => thread.id === current.id) >=
                    selected.threads.length - 1
                  }
                  onClick={() => {
                    const next =
                      selected.threads[
                        selected.threads.findIndex((thread) => thread.id === current.id) + 1
                      ];
                    if (next) select(next, selected.threads);
                  }}
                >
                  [ v ]
                </button>
              </>
            )}
          </div>
          {current.scope.page_path !== path && (
            <p class="muted">
              on {current.scope.page_title || current.scope.page_path}{" "}
              <a href={document.location.origin + current.scope.page_path}>view page</a>
            </p>
          )}
          {missing && (
            <p class="muted">
              the element is no longer on this page; the conversation is still here
            </p>
          )}
          <ThreadView
            key={current.id}
            api={api}
            id={current.id}
            posting={posting}
            recovered={selected?.recovered}
            changed={remember}
          />
        </Popover>
      )}
      {listOpen && (
        <aside class="panel" aria-label="Feedback list panel">
          <AsciiBar title="feedback list" close={() => setListOpen(false)} />
          <div class="panel-body">
            <FeedbackList
              api={api}
              path={path}
              filters={filters}
              changed={setFilters}
              select={select}
            />
          </div>
          <AsciiBar />
        </aside>
      )}
    </>
  );
}

export function Toolbar(props: { api: FeedbackAPI; document: Document; host: Element }) {
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } },
      }),
  );
  return (
    <QueryClientProvider client={client}>
      <FeedbackLayer {...props} />
    </QueryClientProvider>
  );
}
