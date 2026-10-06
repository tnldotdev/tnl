import { usePageFeedback } from "./queries.ts";
import type { FeedbackAPI } from "./api.ts";
import type { Summary } from "./model.ts";
import { supportedAnchor } from "./anchors.ts";

export type ListFilters = { pages: "current" | "all"; state: "open" | "resolved" | "all" };

export function FeedbackList({
  api,
  path,
  filters,
  changed,
  select,
}: {
  api: FeedbackAPI;
  path: string;
  filters: ListFilters;
  changed: (filters: ListFilters) => void;
  select: (thread: Summary, threads: Summary[]) => void;
}) {
  const query = usePageFeedback(
    api,
    filters.pages === "current" ? path : undefined,
    filters.state === "all" ? undefined : filters.state,
  );
  const threads = [
    ...new Map(
      (query.data?.pages.flatMap((page) => page.threads) ?? []).map((thread) => [
        thread.id,
        thread,
      ]),
    ).values(),
  ];
  return (
    <section aria-label="Feedback list">
      <div class="list-filters">
        <label>
          pages
          <select
            value={filters.pages}
            onChange={(event) =>
              changed({
                ...filters,
                pages: event.currentTarget.value === "all" ? "all" : "current",
              })
            }
          >
            <option value="current">this page</option>
            <option value="all">all pages</option>
          </select>
        </label>
        <label>
          status
          <select
            value={filters.state}
            onChange={(event) =>
              changed({
                ...filters,
                state:
                  event.currentTarget.value === "all"
                    ? "all"
                    : event.currentTarget.value === "resolved"
                      ? "resolved"
                      : "open",
              })
            }
          >
            <option value="open">open</option>
            <option value="resolved">resolved</option>
            <option value="all">all</option>
          </select>
        </label>
      </div>
      {query.isPending && <p role="status">loading feedback…</p>}
      {query.error && <p role="status">{query.error.message}</p>}
      {!query.isPending && !query.error && !threads.length && (
        <p class="muted">no feedback here yet</p>
      )}
      <ul class="feedback-cards">
        {threads.map((thread) => (
          <li key={thread.id}>
            <div class="comment-meta">
              <span>
                {thread.report.author?.display_name ?? "anonymous"}
                {thread.report.author && !thread.report.author.verified && (
                  <small> · unverified</small>
                )}
              </span>
              <time dateTime={thread.report.created_at}>
                {new Date(thread.report.created_at).toLocaleString()}
              </time>
            </div>
            {supportedAnchor(thread.anchor)?.selection && (
              <blockquote>{supportedAnchor(thread.anchor)?.selection?.text}</blockquote>
            )}
            <p>{thread.report.text}</p>
            <small>
              {thread.scope.page_title || thread.scope.page_path} · {thread.message_count}{" "}
              {thread.message_count === 1 ? "message" : "messages"}
            </small>
            <div class="card-actions">
              <span class="muted">{thread.state}</span>
              <button
                type="button"
                aria-label={`View ${thread.report.text}`}
                onClick={() => select(thread, threads)}
              >
                view
              </button>
            </div>
          </li>
        ))}
      </ul>
      {query.hasNextPage && (
        <button
          type="button"
          disabled={query.isFetchingNextPage}
          onClick={() => {
            void query.fetchNextPage();
          }}
        >
          more feedback
        </button>
      )}
    </section>
  );
}
