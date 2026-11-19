// records are opaque private bytes. go owns their schema and must store a whole
// identity or certificate record in one put, rather than separate key/cert writes.
export interface PublisherStorage {
  get(key: string): Promise<Uint8Array | undefined>;
  put(key: string, value: Uint8Array): Promise<void>;
  delete(key: string): Promise<void>;
  sync(key: string): Promise<void>;
  withLock<T>(name: string, operation: () => Promise<T>, signal?: AbortSignal): Promise<T>;
}

export type PublisherStorageErrorCode =
  | "sdk.publisher_storage_unavailable"
  | "sdk.publisher_storage_invalid";

// storage engines may include private record values in their exceptions. never
// retain those exceptions as public causes or interpolate a key or value here.
export class PublisherStorageError extends Error {
  readonly code: PublisherStorageErrorCode;

  constructor(code: PublisherStorageErrorCode = "sdk.publisher_storage_unavailable") {
    super(
      code === "sdk.publisher_storage_unavailable"
        ? "publisher storage or exclusive locking is unavailable; provide durable private storage before publishing"
        : "publisher storage contains an invalid record; repair the selected private storage before publishing",
    );
    this.name = "PublisherStorageError";
    this.code = code;
  }
}

export function storageKey(value: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 1024 ||
    value.includes("\0")
  )
    throw new PublisherStorageError("sdk.publisher_storage_invalid");
  return value;
}

export function storageBytes(value: unknown): Uint8Array<ArrayBuffer> {
  if (!(value instanceof Uint8Array) || value.byteLength > 16 * 1024 * 1024)
    throw new PublisherStorageError("sdk.publisher_storage_invalid");
  return Uint8Array.from(value);
}

export function throwIfStorageAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new DOMException("publisher storage lock was aborted", "AbortError");
}
