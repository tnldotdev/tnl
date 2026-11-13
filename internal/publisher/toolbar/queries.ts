import { useEffect, useRef } from "preact/hooks";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { FeedbackAPI } from "./api.ts";
import type { BrowserEvent, FeedbackEvent, Thread } from "./model.ts";
import { FeedbackError, retryFeedback } from "./errors.ts";

export function useViewSignal(): AbortSignal {
  const controller = useRef(new AbortController());
  useEffect(() => () => controller.current.abort(), []);
  return controller.current.signal;
}

export function usePageFeedback(
  api: FeedbackAPI,
  path: string | undefined,
  state?: "open" | "resolved",
) {
  return useInfiniteQuery({
    queryKey: ["feedback-page", path ?? "all-pages", state ?? "all-states"],
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam, signal }) => {
      const page = state
        ? await api.list(path, pageParam, signal, state)
        : await api.list(path, pageParam, signal);
      if (pageParam && page.next_cursor === pageParam) throw new FeedbackError("response_invalid");
      return page;
    },
    getNextPageParam: (page) => page.next_cursor,
    retry: retryFeedback,
    refetchInterval: (query) =>
      query.state.error instanceof FeedbackError && !query.state.error.retryable ? false : 2000,
  });
}

export function mergeEvents(before: FeedbackEvent[], added: FeedbackEvent[]): FeedbackEvent[] {
  return [...new Map([...before, ...added].map((event) => [event.cursor, event])).values()].sort(
    (left, right) => (BigInt(left.cursor) < BigInt(right.cursor) ? -1 : 1),
  );
}

function latestCursor(...values: string[]): string {
  return values.reduce((latest, value) => (BigInt(value) > BigInt(latest) ? value : latest), "0");
}

type Conversation = {
  thread: Thread;
  events: FeedbackEvent[];
  after: string;
  olderCursor: string | undefined;
};

export function useConversation(api: FeedbackAPI, id: string) {
  const client = useQueryClient();
  const key = ["feedback-thread", id];
  const signal = useViewSignal();
  const query = useQuery<Conversation>({
    queryKey: key,
    retry: retryFeedback,
    refetchInterval: (query) =>
      query.state.error instanceof FeedbackError && !query.state.error.retryable ? false : 2000,
    queryFn: async ({ signal }) => {
      const cached = client.getQueryData<Conversation>(key);
      const page = await api.events(id, cached?.after, signal);
      const thread = await api.inspect(id, signal);
      return {
        thread,
        events: mergeEvents(cached?.events ?? [], page.events),
        after: cached
          ? (page.next_cursor ??
            latestCursor(page.event_cursor, ...page.events.map((event) => event.cursor)))
          : page.event_cursor,
        olderCursor: cached ? cached.olderCursor : page.next_cursor,
      };
    },
  });
  const append = useMutation({
    onMutate: () => client.cancelQueries({ queryKey: key }),
    mutationFn: ({
      type,
      text,
      key: retryKey,
    }: {
      type: BrowserEvent;
      text: string;
      key: string;
    }) => api.append(id, type, text, retryKey, signal),
    onSuccess: (event) => {
      client.setQueryData<Conversation>(key, (previous) =>
        previous
          ? {
              ...previous,
              thread: {
                ...previous.thread,
                state:
                  BigInt(event.cursor) <= BigInt(previous.thread.latest_event_cursor)
                    ? previous.thread.state
                    : event.type === "thread.resolved"
                      ? "resolved"
                      : event.type === "thread.reopened"
                        ? "open"
                        : previous.thread.state,
                message_count: (
                  BigInt(previous.thread.message_count) +
                  (BigInt(event.cursor) > BigInt(previous.thread.latest_event_cursor) &&
                  (event.type === "reply" || event.type === "update")
                    ? 1n
                    : 0n)
                ).toString(),
                latest_event_cursor: latestCursor(
                  previous.thread.latest_event_cursor,
                  event.cursor,
                ),
              },
              events: mergeEvents(previous.events, [event]),
            }
          : previous,
      );
      void client.invalidateQueries({ queryKey: ["feedback-page"] });
    },
    onSettled: () => client.invalidateQueries({ queryKey: key }),
  });
  const history = useMutation({
    onMutate: () => client.cancelQueries({ queryKey: key }),
    mutationFn: (cursor: string) => api.events(id, cursor, signal),
    onSuccess: (page) =>
      client.setQueryData<Conversation>(key, (previous) =>
        previous
          ? {
              ...previous,
              events: mergeEvents(previous.events, page.events),
              olderCursor: page.next_cursor,
            }
          : previous,
      ),
  });
  return { query, append, history };
}
