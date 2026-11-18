import * as z from "zod";
import { TnlError } from "../../errors.js";
import type { loadWasm } from "../connector/wasm_loader.js";
import type { WasmPublisherHost } from "../connector/wasm_abi.js";
import type { FetchHandler } from "../publisher/fetch_types.js";
import type { NamedPublicationOptions, Publication } from "../publisher/publication.js";
import {
  bindEnrollment,
  enrollmentSourceSchema,
  type PublisherEnrollment,
} from "../enrollment_source.js";
import { serviceNameSchema } from "../values.js";
import { createBrowserPublisherStorage } from "./storage-browser.js";
import { createPublisherStorageHost } from "./storage-host.js";
import type { PublisherStorage } from "./storage.js";
import {
  portablePublicationOptions,
  publicationError,
  publishPortable,
  type PortablePublication,
} from "./publication.js";

export type { PublisherEnrollment } from "../enrollment_source.js";

export interface PublisherOptions {
  readonly controlUrl?: string;
  /** stable origin-local identity slot; defaults to "default". */
  readonly instance?: string;
  /** needed only on first enrollment or while recovering a lost redemption. */
  readonly enrollment?: PublisherEnrollment;
  readonly publisherStorage?: PublisherStorage;
  readonly signal?: AbortSignal;
}

export interface EnrolledPublisher {
  readonly publisherIdentityID: string;
  readonly deploymentID: string;
  readonly controlUrl: string;
  publish(
    name: string,
    handler: FetchHandler,
    options?: NamedPublicationOptions,
  ): Promise<Publication>;
  close(): Promise<void>;
}

interface RawEnrolledPublisher {
  readonly publisherIdentityID: string;
  readonly deploymentID: string;
  readonly controlUrl: string;
  publish(optionsJSON: string, host: WasmPublisherHost): Promise<unknown>;
  close(): Promise<unknown>;
}

function isEnrolledPublisher(value: unknown): value is RawEnrolledPublisher {
  return (
    typeof value === "object" &&
    value !== null &&
    "publisherIdentityID" in value &&
    typeof value.publisherIdentityID === "string" &&
    /^pub_[A-Za-z0-9]{22}$/.test(value.publisherIdentityID) &&
    "deploymentID" in value &&
    typeof value.deploymentID === "string" &&
    /^dpl_[A-Za-z0-9]{22}$/.test(value.deploymentID) &&
    "controlUrl" in value &&
    typeof value.controlUrl === "string" &&
    (() => {
      const url = URL.parse(value.controlUrl);
      return url?.protocol === "https:" && url.origin === value.controlUrl;
    })() &&
    "publish" in value &&
    typeof value.publish === "function" &&
    "close" in value &&
    typeof value.close === "function"
  );
}

const enrollmentSchema = z.strictObject({
  controlUrl: z.url().max(2048).exactOptional(),
  instance: serviceNameSchema.exactOptional(),
  enrollment: enrollmentSourceSchema.exactOptional(),
  publisherStorage: z
    .custom<PublisherStorage>(
      (v) =>
        typeof v === "object" &&
        v !== null &&
        "get" in v &&
        typeof v.get === "function" &&
        "put" in v &&
        typeof v.put === "function" &&
        "sync" in v &&
        typeof v.sync === "function" &&
        "withLock" in v &&
        typeof v.withLock === "function",
    )
    .exactOptional(),
  signal: z.instanceof(AbortSignal).exactOptional(),
});

const owners = new WeakSet<object>();

export function isEnrolledOwner(owner: object): owner is EnrolledPublisher {
  return owners.has(owner);
}

// the go identity owner keeps signing material in opaque durable records.
// this wrapper owns the runtime and joins publications before releasing its
// cross-tab identity lock. it grants neither management nor connector access.
export async function enrollPortablePublisher(
  options: PublisherOptions,
  loadPublisher: () => ReturnType<typeof loadWasm>,
): Promise<EnrolledPublisher> {
  const parsed = enrollmentSchema.safeParse(options);
  if (!parsed.success) throw new TnlError("sdk.configuration_invalid");
  const selected = parsed.data;
  if (selected.controlUrl !== undefined) {
    const server = new URL(selected.controlUrl);
    if (server.protocol !== "https:" || server.origin !== selected.controlUrl)
      throw new TnlError("sdk.configuration_invalid");
  }
  const lifetime = new AbortController();
  const signal =
    selected.signal === undefined
      ? lifetime.signal
      : AbortSignal.any([lifetime.signal, selected.signal]);
  signal.throwIfAborted();
  let ownedStorage: ReturnType<typeof createBrowserPublisherStorage> | undefined;
  const storage = createPublisherStorageHost(
    selected.publisherStorage ?? (ownedStorage = createBrowserPublisherStorage()),
  );
  let runtime: Awaited<ReturnType<typeof loadWasm>> | undefined;
  let raw: RawEnrolledPublisher | undefined;
  let invalid: { close(): Promise<unknown> } | undefined;
  let closed = false;
  let closing: Promise<void> | undefined;
  const pending = new Set<Promise<unknown>>();
  const publications = new Set<PortablePublication>();
  const close = (): Promise<void> => {
    closed = true;
    signal.removeEventListener("abort", aborted);
    lifetime.abort();
    closing ??= (async () => {
      const stopping = [...publications];
      const results = await Promise.allSettled([...pending, ...stopping.map((p) => p.close())]);
      const alreadyStopping = new Set(stopping);
      results.push(
        ...(await Promise.allSettled(
          [...publications].filter((p) => !alreadyStopping.has(p)).map((p) => p.close()),
        )),
      );
      const owner = raw ?? invalid;
      if (owner !== undefined)
        results.push(...(await Promise.allSettled([Promise.resolve().then(() => owner.close())])));
      if (runtime !== undefined) {
        const current = runtime;
        results.push(
          ...(await Promise.allSettled([
            Promise.resolve().then(() => current.bridge.close()),
            current.exited,
          ])),
        );
      }
      if (ownedStorage !== undefined) {
        try {
          await ownedStorage.close();
        } catch {
          results.push({
            status: "rejected",
            reason: new TnlError("sdk.publication_cleanup_failed"),
          });
        }
      }
      const errors = results.flatMap((r) =>
        r.status === "rejected" && !(r.reason instanceof Error && r.reason.name === "AbortError")
          ? [publicationError(r.reason, "sdk.publication_cleanup_failed")]
          : [],
      );
      if (errors.length > 0) throw new AggregateError(errors, "publisher cleanup failed");
    })();
    return closing;
  };
  const aborted = () => {
    void close().catch(() => {});
  };
  try {
    runtime = await loadPublisher();
    signal.throwIfAborted();
    if (typeof runtime.bridge.enrollPublisher !== "function")
      throw new TnlError("sdk.wasm_invalid");
    const value = await runtime.bridge.enrollPublisher(
      JSON.stringify({
        ...(selected.controlUrl === undefined ? {} : { control_url: selected.controlUrl }),
        instance: selected.instance ?? "default",
      }),
      {
        storage,
        controlFetch: globalThis.fetch.bind(globalThis),
        signal,
        ...(selected.enrollment === undefined
          ? {}
          : { enrollment: bindEnrollment(selected.enrollment, signal) }),
      },
    );
    if (!isEnrolledPublisher(value)) {
      if (
        typeof value === "object" &&
        value !== null &&
        "close" in value &&
        typeof value.close === "function"
      ) {
        const closeInvalid = value.close.bind(value);
        invalid = { close: async () => closeInvalid() };
      }
      throw new TnlError("sdk.wasm_invalid");
    }
    raw = value;
    const owner = value;
    signal.throwIfAborted();
    signal.addEventListener("abort", aborted, { once: true });
    const handle: EnrolledPublisher = Object.freeze({
      publisherIdentityID: raw.publisherIdentityID,
      deploymentID: raw.deploymentID,
      controlUrl: raw.controlUrl,
      async publish(
        name: string,
        handler: FetchHandler,
        options: NamedPublicationOptions = {},
      ): Promise<Publication> {
        if (closed) throw new TnlError("sdk.client_closed");
        if (!serviceNameSchema.safeParse(name).success || typeof handler !== "function")
          throw new TnlError("sdk.configuration_invalid");
        if (pending.size + publications.size >= 32) throw new TnlError("sdk.client_capacity");
        const parsed = portablePublicationOptions(options, true);
        const work = publishPortable({
          bridge: owner,
          selection: { service: name },
          handler,
          storage,
          signal: parsed.signal === undefined ? signal : AbortSignal.any([signal, parsed.signal]),
          certificate: parsed.certificate,
          retain: (p) => publications.add(p),
          release: (p) => publications.delete(p),
        });
        pending.add(work);
        void work.then(
          () => pending.delete(work),
          () => pending.delete(work),
        );
        return work;
      },
      close,
    });
    owners.add(handle);
    return handle;
  } catch (error) {
    const failure = publicationError(error);
    try {
      await close();
    } catch (cleanup) {
      throw new AggregateError([failure, cleanup], "publisher setup and cleanup failed");
    }
    throw failure;
  }
}
