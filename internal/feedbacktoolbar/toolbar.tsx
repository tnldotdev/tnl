import { useEffect, useRef, useState } from "preact/hooks";
import {
  QueryClient,
  QueryClientProvider,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import * as z from "zod/mini";
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

type Draft = { path: string; target?: AnchorTarget | undefined; key: string };
type Selected = { thread: Summary; threads: Summary[] };
const browserStatusSchema = z.object({
  signed_in: z.boolean(),
  display_name: z.optional(z.string()),
  team_member: z.optional(z.boolean()),
});

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
  const [placing, setPlacing] = useState(false);
  const [draft, setDraft] = useState<Draft>();
  const [selected, setSelected] = useState<Selected>();
  const [listOpen, setListOpen] = useState(false);
  const [filters, setFilters] = useState<ListFilters>({ pages: "current", state: "open" });
  const actions = useRef<Action[]>([{ type: "navigation", path: document.location.pathname }]);
  const toolbar = useRef<HTMLDivElement>(null);
  const client = useQueryClient();
  const browserStatus = useQuery({
    queryKey: ["feedback-browser-status"],
    queryFn: async ({ signal }) => {
      const response = await document.defaultView?.fetch("/__tnl/team/session", {
        credentials: "same-origin",
        signal,
      });
      if (!response?.ok) throw new Error("account status is unavailable");
      return browserStatusSchema.parse((await response.json()) as unknown);
    },
    retry: false,
    refetchInterval: 30_000,
  });
  const signOut = useMutation({
    mutationFn: async () => {
      const response = await document.defaultView?.fetch("/__tnl/team/logout", {
        method: "POST",
        credentials: "same-origin",
      });
      if (!response?.ok) throw new Error("could not sign out of this preview");
    },
    onSuccess: () => client.invalidateQueries({ queryKey: ["feedback-browser-status"] }),
  });
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
        setDraft(undefined);
        setSelected(undefined);
        setPlacing(false);
        actions.current = [
          ...actions.current.slice(-19),
          { type: "navigation", path: document.location.pathname },
        ];
      }
    }, 500);
    return () => window.clearInterval(timer);
  }, [document, path]);
  function newDraft(target?: AnchorTarget): void {
    setPlacing(false);
    setListOpen(false);
    setSelected(undefined);
    setDraft({ path, target, key: crypto.randomUUID() });
  }
  function select(thread: Summary, choices: Summary[]): void {
    setSelected({ thread, threads: choices });
    setDraft(undefined);
    setListOpen(false);
    setPlacing(false);
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
        {browserStatus.data?.signed_in ? (
          <>
            <span class="muted">signed in as {browserStatus.data.display_name}</span>
            <button type="button" onClick={() => signOut.mutate()}>
              [ sign out ]
            </button>
          </>
        ) : browserStatus.data ? (
          <a class="account-link" href={"/__tnl/team/login?return=" + encodeURIComponent(path)}>
            [ sign in ]
          </a>
        ) : null}
        {signOut.error && <small role="status">{signOut.error.message}</small>}
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
          disabled={!!draft}
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
          close={() => setDraft(undefined)}
        >
          <ReportForm
            key={draft.key}
            api={api}
            path={draft.path}
            document={document}
            actions={() => actions.current}
            target={draft.target}
            browserName={
              browserStatus.data?.signed_in ? browserStatus.data.display_name : undefined
            }
            cancel={() => setDraft(undefined)}
            saved={(thread) => {
              setDraft(undefined);
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
          close={() => setSelected(undefined)}
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
          <ThreadView key={current.id} api={api} id={current.id} />
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
