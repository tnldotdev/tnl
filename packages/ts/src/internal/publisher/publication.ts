import { TnlError } from "../../errors.js";
import { runtimeRequest, type RuntimeEndpoint } from "./local.js";
import {
  parseStatus,
  parseEvents,
  statusCursor,
  type PublicationStatus,
  type PublicationEvent,
} from "./status.js";

export type { PublicationStatus, PublicationEvent } from "./status.js";

export interface Publication {
  readonly url: `https://${string}` | undefined;
  status(options?: { readonly signal?: AbortSignal }): Promise<PublicationStatus>;
  wait(options?: {
    readonly until?: "ready" | "routable";
    readonly signal?: AbortSignal;
  }): Promise<void>;
  watch(options?: {
    readonly after?: string;
    readonly signal?: AbortSignal;
  }): AsyncIterable<PublicationEvent>;
  finished(): Promise<void>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

export interface PublicationSelection {
  readonly endpoint: RuntimeEndpoint;
  readonly service: string;
  readonly registrationID: string;
  readonly target: string;
}

// observation owns only its wait; cancellation never stops the publication.
export function publicationHandle(options: {
  current(): PublicationSelection;
  url(): `https://${string}` | undefined;
  readonly lifetime: AbortSignal;
  close(): Promise<void>;
  finished(): Promise<void>;
  request?: typeof runtimeRequest;
}): Publication {
  const request = options.request ?? runtimeRequest;
  const signalFor = (signal?: AbortSignal) =>
    signal === undefined ? options.lifetime : AbortSignal.any([signal, options.lifetime]);
  const read = async (operation: "status" | "check", signal: AbortSignal) => {
    signal.throwIfAborted();
    const current = options.current();
    const raw = await request(
      current.endpoint,
      operation,
      operation === "check" ? { services: [current.service] } : undefined,
      signal,
    );
    signal.throwIfAborted();
    const latest = options.current();
    if (
      latest.registrationID !== current.registrationID ||
      latest.target !== current.target ||
      latest.endpoint.owner_id !== current.endpoint.owner_id
    )
      throw new TnlError("sdk.registration_stale");
    const status = parseStatus(raw, current.service, current.registrationID, current.target);
    if (status === undefined) throw new TnlError("sdk.registration_stale");
    return { status, raw };
  };
  const pause = async (signal: AbortSignal) => {
    signal.throwIfAborted();
    await new Promise<void>((resolve, reject) => {
      const stop = () => {
        clearTimeout(timer);
        reject(signal.reason);
      };
      const timer = setTimeout(() => {
        signal.removeEventListener("abort", stop);
        resolve();
      }, 250);
      signal.addEventListener("abort", stop, { once: true });
    });
  };
  let finished: Promise<void> | undefined;
  return Object.freeze({
    get url() {
      return options.url();
    },
    async status(input: { readonly signal?: AbortSignal } = {}) {
      return (await read("status", signalFor(input.signal))).status;
    },
    async wait(
      input: { readonly until?: "ready" | "routable"; readonly signal?: AbortSignal } = {},
    ) {
      const signal = signalFor(input.signal);
      const started = Date.now();
      for (;;) {
        const { status } = await read(input.until === "routable" ? "status" : "check", signal);
        if (status.failure !== undefined) throw new TnlError("sdk.publication_failed");
        if (
          input.until === "routable"
            ? status.routable
            : status.ready &&
              status.checkedAt !== undefined &&
              Date.parse(status.checkedAt) >= started
        )
          return;
        await pause(signal);
      }
    },
    async *watch(input: { readonly after?: string; readonly signal?: AbortSignal } = {}) {
      const signal = signalFor(input.signal);
      let cursor = input.after;
      const initial = await read("status", signal);
      if (cursor === undefined) {
        const { raw } = initial;
        const snapshot = statusCursor(raw);
        cursor = snapshot.cursor;
        // the native status read already checked registration and scope.
        const [event] = parseEvents(
          [{ cursor, type: "snapshot", at: snapshot.at, snapshot: raw }],
          options.current().service,
        );
        if (event !== undefined) yield event;
      }
      for (;;) {
        signal.throwIfAborted();
        const current = options.current();
        const raw = await request(current.endpoint, "events", { after: cursor }, signal);
        signal.throwIfAborted();
        const events = parseEvents(raw, current.service, initial.status.tunnelID);
        for (const event of events) {
          cursor = event.cursor;
          yield event;
        }
        await pause(signal);
      }
    },
    close: options.close,
    finished() {
      if (finished !== undefined) return finished;
      const observing = new AbortController();
      const signal = signalFor(observing.signal);
      const monitor = async () => {
        for (;;) {
          try {
            const { status } = await read("status", signal);
            if (status.failure !== undefined) throw new TnlError("sdk.publication_failed");
          } catch (error) {
            if (signal.aborted) {
              // cleanup completion, not an observation abort, owns termination.
              return options.finished();
            }
            if (
              !(error instanceof TnlError) ||
              (error.code !== "sdk.dev_unavailable" && error.code !== "sdk.registration_stale")
            )
              throw error;
          }
          try {
            await pause(signal);
          } catch {
            return options.finished();
          }
        }
      };
      finished = Promise.race([options.finished(), monitor()]).finally(() => observing.abort());
      return finished;
    },
    [Symbol.asyncDispose]: options.close,
  });
}
