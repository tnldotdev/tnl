import { TnlError } from "../../errors.js";
import type { TnlClientFactory, TnlClientOptions } from "../../project.js";

type Entry<Client> = {
  readonly created: Promise<Client>;
  closed: boolean;
};

// native selects the exact binding; this cache owns only ordinary driver values.
// expiry is deliberately absent from its key: native owns renewable authority.
export function clientFactory<Connection, Client>(
  acquire: () => Promise<{ readonly key: string; readonly connection: Connection }>,
  options: TnlClientOptions<Connection, Client>,
): TnlClientFactory<Client> {
  if (typeof options?.create !== "function" || typeof options.close !== "function")
    throw new TnlError("sdk.configuration_invalid");
  const entries = new Map<string, Entry<Client>>();
  const pending = new Set<Promise<Client>>();
  const closedError = new TnlError("sdk.client_closed");
  let closed = false;
  let closing: Promise<void> | undefined;

  const get = (): Promise<Client> => {
    if (closed) return Promise.reject(closedError);
    // register before invoking acquisition or application callbacks. close joins
    // every admitted getter, including one still waiting for native selection.
    const operation = Promise.resolve().then(async () => {
      if (closed) throw closedError;
      const binding = await acquire();
      if (closed) throw closedError;
      let entry = entries.get(binding.key);
      if (entry === undefined) {
        if (entries.size >= 64) throw new TnlError("sdk.client_capacity");
        const created: Promise<Client> = Promise.resolve().then(async () => {
          if (closed) throw closedError;
          return options.create(binding.connection);
        });
        entry = { created, closed: false };
        const selected = entry;
        entries.set(binding.key, selected);
        void created.catch(() => {
          if (entries.get(binding.key) === selected) entries.delete(binding.key);
        });
      }
      const value = await entry.created;
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
      const attempt = (async () => {
        await Promise.allSettled(pending);
        const results = await Promise.allSettled(
          [...entries].map(async ([key, entry]) => {
            if (entry.closed) return;
            const value = await entry.created;
            await options.close(value);
            entry.closed = true;
            if (entries.get(key) === entry) entries.delete(key);
          }),
        );
        const failures = results.flatMap((result) =>
          result.status === "rejected" ? [result.reason as unknown] : [],
        );
        if (failures.length === 1) throw failures[0];
        if (failures.length > 1) throw new AggregateError(failures, "client cleanup failed");
      })();
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
