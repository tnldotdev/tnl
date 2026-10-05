import { useEffect, useRef } from "preact/hooks";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { FeedbackAPI } from "./api.ts";
import type { BrowserEvent, FeedbackEvent, Thread } from "./model.ts";

export function useViewSignal(): AbortSignal {
  const controller = useRef(new AbortController());
  useEffect(() => () => controller.current.abort(), []);
  return controller.current.signal;
}

export function usePageFeedback(api: FeedbackAPI, path: string) {
  return useInfiniteQuery({
    queryKey: ["feedback-page", path],
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam, signal }) => {
      const page = await api.list(path, pageParam, signal);
      if (pageParam && page.next_cursor === pageParam)
        throw new Error("the server repeated a feedback page");
      return page;
    },
    getNextPageParam: (page) => page.next_cursor,
    refetchInterval: 2000,
  });
}

function mergeEvents(before: FeedbackEvent[], added: FeedbackEvent[]): FeedbackEvent[] {
  return [...new Map([...before, ...added].map((event) => [event.cursor, event])).values()].sort(
    (left, right) => left.cursor - right.cursor,
  );
}

type Conversation = {
  thread: Thread;
  events: FeedbackEvent[];
  after: number;
  olderCursor: number | undefined;
};

export function useConversation(api: FeedbackAPI, id: string) {
  const client = useQueryClient();
  const key = ["feedback-thread", id];
  const signal = useViewSignal();
  const query = useQuery({
    queryKey: key,
    refetchInterval: 2000,
    queryFn: async ({ signal }) => {
      const cached = client.getQueryData<Conversation>(key);
      const page = await api.events(id, cached?.after, signal);
      const thread = await api.inspect(id, signal);
      return {
        thread,
        events: mergeEvents(cached?.events ?? [], page.events),
        after: cached
          ? (page.next_cursor ??
            Math.max(page.event_cursor, ...page.events.map((event) => event.cursor)))
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
                  event.type === "thread.resolved"
                    ? "resolved"
                    : event.type === "thread.reopened"
                      ? "open"
                      : previous.thread.state,
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
    mutationFn: (cursor: number) => api.events(id, cursor, signal),
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
