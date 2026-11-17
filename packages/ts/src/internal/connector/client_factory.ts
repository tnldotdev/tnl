import { TnlError } from "../../errors.js";
import type { TnlClientFactory, TnlClientOptions } from "../../project.js";
import { cancellable, shutdownBudget } from "./cancellation.js";

type Entry<Client> = {
  readonly created: Promise<Client>;
  cleanup?: Promise<void>;
  settled?: boolean;
  failure?: { readonly cause: unknown };
};

// native selects the exact binding; this cache owns only ordinary driver values.
// expiry is deliberately absent from its key: native owns renewable authority.
export function clientFactory<Connection, Client>(
  acquire: (
    closedError: TnlError,
  ) => Promise<{ readonly key: string; readonly connection: Connection }>,
  options: TnlClientOptions<Connection, Client>,
  parent?: () => number | undefined,
): TnlClientFactory<Client> {
  if (typeof options?.create !== "function" || typeof options.close !== "function")
    throw new TnlError("sdk.configuration_invalid");
  const entries = new Map<string, Entry<Client>>();
  const pending = new Set<Promise<Client>>();
  const closedError = new TnlError("sdk.client_closed");
  let closed = false;
  let closing: Promise<void> | undefined;
  let until: number | undefined;
  const lifetime = new AbortController();

  const get = (): Promise<Client> => {
    if (closed) return Promise.reject(closedError);
    // register before invoking acquisition or application callbacks. close joins
    // every admitted getter, including one still waiting for native selection.
    const operation = Promise.resolve().then(async () => {
      if (closed) throw closedError;
      const binding = await acquire(closedError);
      if (closed) throw closedError;
      let entry = entries.get(binding.key);
      if (entry === undefined) {
        if (entries.size >= 64) throw new TnlError("sdk.client_capacity");
        const created: Promise<Client> = Promise.resolve().then(async () => {
          if (closed) throw closedError;
          return options.create(binding.connection);
        });
        entry = { created };
        const selected = entry;
        entries.set(binding.key, selected);
        void created.catch(() => {
          if (!closed && entries.get(binding.key) === selected) entries.delete(binding.key);
        });
      }
      const value = await cancellable(lifetime.signal, () => entry.created);
      if (closed) throw closedError;
      return value;
    });
    pending.add(operation);
    void operation.then(
      () => pending.delete(operation),
      () => pending.delete(operation),
    );
    return operation;
  };

  return Object.assign(get, {
    close(): Promise<void> {
      closed = true;
      if (closing !== undefined) return closing;
      const budget = shutdownBudget(Math.min(until ?? Infinity, parent?.() ?? Infinity));
      until = budget.until;
      const interrupt = () => lifetime.abort(budget.signal.reason);
      budget.signal.addEventListener("abort", interrupt, { once: true });
      if (budget.signal.aborted) interrupt();
      const attempt = (async () => {
        // every retained client starts cleanup independently. the budget bounds
        // our wait, not ownership of a late value or an in-flight close callback.
        const retained = [...entries];
        const cleanups = retained.map(([key, entry]) => {
          if (
            entry.cleanup === undefined ||
            (entry.failure !== undefined && !budget.signal.aborted)
          ) {
            delete entry.failure;
            entry.settled = false;
            entry.cleanup = entry.created
              .then(async (value) => {
                await options.close(value);
                if (entries.get(key) === entry) entries.delete(key);
              })
              .then(
                () => {
                  entry.settled = true;
                },
                (cause: unknown) => {
                  entry.settled = true;
                  entry.failure = { cause };
                  throw cause;
                },
              );
            void entry.cleanup.catch(() => {});
          }
          return entry.cleanup;
        });
        const joining = Promise.allSettled([...pending, ...cleanups]);
        const failures: unknown[] = [];
        try {
          const results =
            pending.size === 0 && retained.every(([, entry]) => entry.settled)
              ? await joining
              : await cancellable(budget.signal, () => joining);
          for (const result of results)
            if (result.status === "rejected" && result.reason !== closedError)
              failures.push(result.reason);
        } catch (cause) {
          failures.push(cause);
          for (const [, entry] of retained)
            if (entry.failure !== undefined) failures.push(entry.failure.cause);
        }
        const unique = [...new Set(failures)];
        if (unique.length === 1) throw unique[0];
        if (unique.length > 1) throw new AggregateError(unique, "client cleanup failed");
      })().finally(() => {
        budget.signal.removeEventListener("abort", interrupt);
        budget.finish();
      });
      closing = attempt;
      void attempt.then(
        () => {
          if (closing === attempt) closing = undefined;
        },
        () => {
          if (closing === attempt) closing = undefined;
        },
      );
      return attempt;
    },
  });
}
