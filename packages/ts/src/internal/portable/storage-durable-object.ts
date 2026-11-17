import {
  PublisherStorageError,
  storageBytes,
  storageKey,
  throwIfStorageAborted,
  type PublisherStorage,
} from "./storage.js";

export type PublisherSQLiteValue = string | number | null | ArrayBuffer;

// the attached sqlite api is structural so neither this module nor browser
// entrypoints import a cloudflare runtime or a provider-specific type package.
export interface PublisherSQLiteStorage {
  readonly sql: {
    exec<T extends Record<string, PublisherSQLiteValue>>(
      query: string,
      ...bindings: PublisherSQLiteValue[]
    ): { toArray(): T[] };
  };
  sync(): Promise<void>;
}

const lockQueues = new WeakMap<object, Map<string, Promise<void>>>();

export function createDurableObjectPublisherStorage(
  storage: PublisherSQLiteStorage,
  namespace = "default",
): PublisherStorage {
  const selectedNamespace = storageKey(namespace);
  const prefix = `${selectedNamespace.length}:${selectedNamespace}:`;
  if (
    storage?.sql === undefined ||
    typeof storage.sql.exec !== "function" ||
    typeof storage.sync !== "function"
  )
    throw new PublisherStorageError();
  try {
    storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS tnl_publisher_records_v1 (key TEXT PRIMARY KEY, value BLOB NOT NULL)",
    );
  } catch {
    throw new PublisherStorageError();
  }
  let locks = lockQueues.get(storage.sql);
  if (locks === undefined) {
    locks = new Map();
    lockQueues.set(storage.sql, locks);
  }
  const queues = locks;
  return Object.freeze({
    async get(key: string): Promise<Uint8Array | undefined> {
      let rows: { value: PublisherSQLiteValue }[];
      try {
        rows = storage.sql
          .exec<{ value: PublisherSQLiteValue }>(
            "SELECT value FROM tnl_publisher_records_v1 WHERE key = ?",
            prefix + storageKey(key),
          )
          .toArray();
      } catch {
        throw new PublisherStorageError();
      }
      if (rows.length === 0) return undefined;
      const value = rows[0]?.value;
      if (!(value instanceof ArrayBuffer))
        throw new PublisherStorageError("sdk.publisher_storage_invalid");
      return storageBytes(new Uint8Array(value));
    },
    async put(key: string, value: Uint8Array): Promise<void> {
      const record = storageBytes(value);
      try {
        // one sqlite statement replaces the whole record atomically.
        storage.sql.exec(
          "INSERT INTO tnl_publisher_records_v1 (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
          prefix + storageKey(key),
          record.buffer,
        );
      } catch {
        throw new PublisherStorageError();
      }
    },
    async delete(key: string): Promise<void> {
      try {
        storage.sql.exec(
          "DELETE FROM tnl_publisher_records_v1 WHERE key = ?",
          prefix + storageKey(key),
        );
      } catch {
        throw new PublisherStorageError();
      }
    },
    async sync(key: string): Promise<void> {
      storageKey(key);
      try {
        await storage.sync();
      } catch {
        throw new PublisherStorageError();
      }
    },
    async withLock<T>(name: string, operation: () => Promise<T>, signal?: AbortSignal): Promise<T> {
      throwIfStorageAborted(signal);
      const key = prefix + storageKey(name);
      const preceding = queues.get(key) ?? Promise.resolve();
      let release!: () => void;
      const held = new Promise<void>((resolve) => {
        release = resolve;
      });
      const queued = preceding.then(() => held);
      queues.set(key, queued);
      // a durable object has one live isolate. this queue covers await
      // interleaving within it; sqlite owns durability across isolate replacement.
      // never hold a transaction open while a certificate request is on the network.
      try {
        await waitForLock(preceding, signal);
        throwIfStorageAborted(signal);
        return await operation();
      } finally {
        release();
        void queued.then(() => {
          if (queues.get(key) === queued) queues.delete(key);
        });
      }
    },
  });
}

async function waitForLock(preceding: Promise<void>, signal?: AbortSignal): Promise<void> {
  if (signal === undefined) return preceding;
  throwIfStorageAborted(signal);
  let abort!: () => void;
  const canceled = new Promise<never>((_resolve, reject) => {
    abort = () => reject(new DOMException("publisher storage lock was aborted", "AbortError"));
    signal.addEventListener("abort", abort, { once: true });
  });
  try {
    await Promise.race([preceding, canceled]);
  } finally {
    signal.removeEventListener("abort", abort);
  }
}
