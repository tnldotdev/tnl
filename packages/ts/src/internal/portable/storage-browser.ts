import {
  PublisherStorageError,
  storageBytes,
  storageKey,
  throwIfStorageAborted,
  type PublisherStorage,
} from "./storage.js";

export interface BrowserPublisherStorageOptions {
  readonly database?: string;
  readonly indexedDB?: IDBFactory;
  readonly locks?: LockManager;
}

// indexeddb provides atomic record replacement; web locks cover the longer
// read/prepare/network/write sequence across tabs and workers on the same origin.
// this storage is private to the origin, not a defense against same-origin code.
export function createBrowserPublisherStorage(
  options: BrowserPublisherStorageOptions = {},
): PublisherStorage & { close(): Promise<void> } {
  const factory = options.indexedDB ?? globalThis.indexedDB;
  const locks = options.locks ?? globalThis.navigator?.locks;
  if (factory === undefined || locks === undefined || typeof locks.request !== "function")
    throw new PublisherStorageError();
  const databaseName = storageKey(options.database ?? "tnl-publisher-v1");
  let opening: Promise<IDBDatabase> | undefined;
  let closed = false;

  const database = (): Promise<IDBDatabase> => {
    if (closed) return Promise.reject(new PublisherStorageError());
    opening ??= new Promise<IDBDatabase>((resolve, reject) => {
      let request: IDBOpenDBRequest;
      try {
        request = factory.open(databaseName, 1);
      } catch {
        reject(new PublisherStorageError());
        return;
      }
      let failed = false;
      const fail = () => {
        failed = true;
        reject(new PublisherStorageError());
      };
      request.onblocked = fail;
      request.onerror = fail;
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains("records"))
          request.result.createObjectStore("records");
      };
      request.onsuccess = () => {
        const db = request.result;
        if (failed || closed) {
          db.close();
          fail();
          return;
        }
        db.onversionchange = () => {
          closed = true;
          db.close();
        };
        resolve(db);
      };
    });
    return opening;
  };

  const transaction = async <T>(
    mode: IDBTransactionMode,
    operation: (store: IDBObjectStore) => IDBRequest<T>,
  ): Promise<T> => {
    const db = await database();
    return new Promise<T>((resolve, reject) => {
      try {
        const tx = db.transaction(
          "records",
          mode,
          mode === "readwrite" ? { durability: "strict" } : {},
        );
        const request = operation(tx.objectStore("records"));
        // request success alone is not a commit: quota and i/o failures can still
        // abort the transaction after the put request has succeeded.
        tx.oncomplete = () => resolve(request.result);
        tx.onabort = () => reject(new PublisherStorageError());
        tx.onerror = () => reject(new PublisherStorageError());
      } catch {
        reject(new PublisherStorageError());
      }
    });
  };

  return Object.freeze({
    async get(key: string): Promise<Uint8Array | undefined> {
      const value: unknown = await transaction("readonly", (store) => store.get(storageKey(key)));
      return value === undefined ? undefined : storageBytes(value);
    },
    async put(key: string, value: Uint8Array): Promise<void> {
      const record = storageBytes(value);
      await transaction("readwrite", (store) => store.put(record, storageKey(key)));
    },
    async delete(key: string): Promise<void> {
      await transaction("readwrite", (store) => store.delete(storageKey(key)));
    },
    async sync(key: string): Promise<void> {
      storageKey(key);
      // put resolves only after a strict-durability transaction commits.
      await database();
    },
    async withLock<T>(name: string, operation: () => Promise<T>, signal?: AbortSignal): Promise<T> {
      throwIfStorageAborted(signal);
      let entered = false;
      try {
        return await locks.request(
          `tnl-publisher:${JSON.stringify([databaseName, storageKey(name)])}`,
          { mode: "exclusive", ...(signal === undefined ? {} : { signal }) },
          async () => {
            entered = true;
            throwIfStorageAborted(signal);
            return operation();
          },
        );
      } catch (error) {
        if (entered) throw error;
        throwIfStorageAborted(signal);
        throw new PublisherStorageError();
      }
    },
    async close(): Promise<void> {
      closed = true;
      if (opening !== undefined) {
        try {
          (await opening).close();
        } catch {
          // opening already reported the storage failure.
        }
      }
    },
  });
}
