import {
  PublisherStorageError,
  storageBytes,
  storageKey,
  throwIfStorageAborted,
  type PublisherStorage,
} from "./storage.js";

export interface PublisherStorageHost {
  read(
    scopeJSON: string,
    key: string,
    limit: number,
    signal: AbortSignal,
  ): Promise<Uint8Array | null>;
  write(scopeJSON: string, key: string, bytes: Uint8Array, signal: AbortSignal): Promise<void>;
  sync(scopeJSON: string, key: string, signal: AbortSignal): Promise<void>;
  lock(scopeJSON: string, key: string, signal: AbortSignal): Promise<() => Promise<void>>;
}

// adapt one atomic private-record store to go's certificate-storage host abi.
// scope is part of both record and lock identity, never an authorization grant.
export function createPublisherStorageHost(storage: PublisherStorage): PublisherStorageHost {
  if (
    storage === undefined ||
    storage === null ||
    ![storage.get, storage.put, storage.sync, storage.withLock].every(
      (method) => typeof method === "function",
    )
  )
    throw new PublisherStorageError();
  const scopedKey = async (scopeJSON: string, key: string): Promise<string> => {
    storageKey(key);
    let scope: unknown;
    try {
      scope = JSON.parse(scopeJSON);
    } catch {
      throw new PublisherStorageError("sdk.publisher_storage_invalid");
    }
    if (
      typeof scope !== "object" ||
      scope === null ||
      Array.isArray(scope) ||
      !("control_url" in scope) ||
      !scopeText(scope.control_url)
    )
      throw new PublisherStorageError("sdk.publisher_storage_invalid");
    const count = Object.keys(scope).length;
    let canonical: string;
    if (
      count === 2 &&
      "enrollment_selection" in scope &&
      typeof scope.enrollment_selection === "string" &&
      /^[0-9a-f]{64}$/.test(scope.enrollment_selection)
    ) {
      canonical = JSON.stringify([
        "enrollment",
        scope.control_url,
        scope.enrollment_selection,
        key,
      ]);
    } else if (
      count === 3 &&
      "team_id" in scope &&
      scopeText(scope.team_id, true) &&
      "publisher_identity_id" in scope &&
      scopeText(scope.publisher_identity_id)
    ) {
      canonical = JSON.stringify([
        scope.control_url,
        scope.team_id,
        scope.publisher_identity_id,
        key,
      ]);
    } else {
      throw new PublisherStorageError("sdk.publisher_storage_invalid");
    }
    try {
      const digest = new Uint8Array(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical)),
      );
      return `scope:${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
    } catch {
      throw new PublisherStorageError();
    }
  };

  return Object.freeze({
    async read(
      scopeJSON: string,
      key: string,
      limit: number,
      signal: AbortSignal,
    ): Promise<Uint8Array | null> {
      throwIfStorageAborted(signal);
      if (!Number.isSafeInteger(limit) || limit < 0 || limit > 16 * 1024 * 1024)
        throw new PublisherStorageError("sdk.publisher_storage_invalid");
      const name = await scopedKey(scopeJSON, key);
      const record = await protect(async () => {
        const value = await storage.get(name);
        if (value === undefined) return null;
        if (value.byteLength > limit)
          throw new PublisherStorageError("sdk.publisher_storage_invalid");
        return storageBytes(value);
      }, signal);
      throwIfStorageAborted(signal);
      return record;
    },
    async write(
      scopeJSON: string,
      key: string,
      bytes: Uint8Array,
      signal: AbortSignal,
    ): Promise<void> {
      throwIfStorageAborted(signal);
      const record = storageBytes(bytes);
      const name = await scopedKey(scopeJSON, key);
      await protect(async () => {
        await storage.put(name, record);
        // go's Write requires durable success. join sync even if cancellation
        // arrived during put; a later standalone Sync must not repair this write.
        await storage.sync(name);
      }, signal);
      throwIfStorageAborted(signal);
    },
    async sync(scopeJSON: string, key: string, signal: AbortSignal): Promise<void> {
      throwIfStorageAborted(signal);
      const name = await scopedKey(scopeJSON, key);
      await protect(() => storage.sync(name), signal);
      throwIfStorageAborted(signal);
    },
    async lock(scopeJSON: string, key: string, signal: AbortSignal): Promise<() => Promise<void>> {
      throwIfStorageAborted(signal);
      const name = await scopedKey(scopeJSON, key);
      let acquired!: (release: () => Promise<void>) => void;
      let failed!: (error: unknown) => void;
      const result = new Promise<() => Promise<void>>((resolve, reject) => {
        acquired = resolve;
        failed = reject;
      });
      let release!: () => void;
      const held = new Promise<void>((resolve) => {
        release = resolve;
      });
      const ownership = Promise.resolve().then(() =>
        storage.withLock(
          name,
          async () => {
            acquired(async () => {
              release();
              await protect(() => ownership);
            });
            await held;
          },
          signal,
        ),
      );
      void ownership.catch((error: unknown) => failed(safeStorageError(error, signal)));
      return result;
    },
  });
}

async function protect<T>(operation: () => Promise<T>, signal?: AbortSignal): Promise<T> {
  throwIfStorageAborted(signal);
  try {
    return await operation();
  } catch (error) {
    throw safeStorageError(error, signal);
  }
}

function safeStorageError(error: unknown, signal?: AbortSignal): Error {
  const canceled = signal?.aborted
    ? new DOMException("publisher storage operation was aborted", "AbortError")
    : undefined;
  if (canceled !== undefined && error instanceof DOMException && error.name === "AbortError")
    return canceled;
  const failure = new PublisherStorageError(
    error instanceof PublisherStorageError && error.code === "sdk.publisher_storage_invalid"
      ? "sdk.publisher_storage_invalid"
      : "sdk.publisher_storage_unavailable",
  );
  // cancellation is not proof that a concurrent storage operation succeeded.
  // retain both facts, but never retain the provider's private error or cause.
  return canceled === undefined
    ? failure
    : new AggregateError([failure, canceled], "publisher storage failed during cancellation");
}

function scopeText(value: unknown, allowEmpty = false): value is string {
  return (
    typeof value === "string" &&
    (allowEmpty || value.length > 0) &&
    value.length <= 4096 &&
    !value.includes("\0")
  );
}
