import { spawn } from "node:child_process";
import { isIP } from "node:net";
import * as z from "zod";
import { TnlError } from "../../errors.js";
import { resolveNativeBinary } from "../native/launcher.js";
import { launchEnvironment } from "../tracing.js";
import { serviceNameSchema } from "../values.js";
import {
  bindEnrollment,
  enrollmentSourceSchema,
  type PublisherEnrollment,
} from "../enrollment_source.js";
import type { FetchHandler } from "./fetch_types.js";
import { parseOwnerEndpoint, publisherInvocationEndpoint } from "./local.js";
import {
  nativePublicationRuntime,
  publishFetch,
  publishServer,
  validatePublicationOptions,
  type NamedPublicationOptions,
  type Publication,
  type PublicationSelection,
} from "./publication.js";
import type { LocalHTTPServer } from "./register.js";

const controlSchema = z
  .string()
  .max(2048)
  .refine((value) => {
    const origin = URL.parse(value);
    if (origin === null || origin.origin !== value) return false;
    const host = origin.hostname;
    return (
      origin.protocol === "https:" ||
      (origin.protocol === "http:" &&
        (host === "localhost" || host === "[::1]" || (isIP(host) === 4 && host.startsWith("127."))))
    );
  });
const optionsSchema = z.strictObject({
  instance: serviceNameSchema.exactOptional(),
  controlUrl: controlSchema.exactOptional(),
  enrollment: enrollmentSourceSchema.exactOptional(),
  signal: z.instanceof(AbortSignal).exactOptional(),
});
const readySchema = z.strictObject({
  type: z.literal("ready"),
  publisher_identity_id: z.string().regex(/^pub_[A-Za-z0-9]{22}$/),
  deployment_id: z.string().regex(/^dpl_[A-Za-z0-9]{22}$/),
  control_url: controlSchema,
  endpoint: z.unknown(),
});
const challengeSchema = z.strictObject({ type: z.literal("enrollment") });

export interface PublisherOptions {
  readonly controlUrl?: string;
  readonly instance?: string;
  readonly enrollment?: PublisherEnrollment;
  readonly signal?: AbortSignal;
}

declare const nativePublisher: unique symbol;
export interface Publisher {
  readonly [nativePublisher]: true;
  readonly publisherIdentityID: string;
  readonly deploymentID: string;
  readonly controlUrl: string;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

type PublishService = (
  service: string,
  target: FetchHandler | LocalHTTPServer,
  options?: NamedPublicationOptions,
) => Promise<Publication>;
const owners = new WeakMap<object, PublishService>();

export function nativePublisherOperation(owner: object): PublishService | undefined {
  return owners.get(owner);
}

export async function publisher(options: PublisherOptions = {}): Promise<Publisher> {
  const parsed = optionsSchema.safeParse(options);
  if (!parsed.success) throw new TnlError("sdk.configuration_invalid");
  const selected = parsed.data;
  selected.signal?.throwIfAborted();
  const lifetime = new AbortController();
  const startup = AbortSignal.any([lifetime.signal, AbortSignal.timeout(30_000)]);
  const environment = { ...process.env };
  delete environment.TNL_ENROLLMENT_KEY;
  const child = spawn(
    resolveNativeBinary(),
    [
      "--no-telemetry",
      "runtime",
      "publisher",
      "--instance",
      selected.instance ?? "default",
      ...(selected.controlUrl === undefined ? [] : ["--control-url", selected.controlUrl]),
    ],
    { env: launchEnvironment(environment), stdio: ["pipe", "pipe", "ignore"] },
  );
  child.stdin.on("error", () => {});
  let launchError = false;
  const exited = new Promise<number | null>((resolve) => {
    child.once("error", () => {
      launchError = true;
    });
    child.once("close", (code) => {
      lifetime.abort(new TnlError("sdk.dev_unavailable"));
      resolve(launchError ? null : code);
    });
  });
  let stopping: Promise<void> | undefined;
  function stopNative(): Promise<void> {
    return (stopping ??= (async () => {
      child.stdin.end();
      child.stdout.resume();
      const kill = setTimeout(() => child.kill("SIGKILL"), 12_000);
      try {
        if ((await exited) !== 0) throw new TnlError("sdk.publication_cleanup_failed");
      } finally {
        clearTimeout(kill);
      }
    })());
  }
  const abortStartup = () => lifetime.abort(selected.signal?.reason);
  selected.signal?.addEventListener("abort", abortStartup, { once: true });
  const stoppingStartup = () => {
    void stopNative().catch(() => {});
  };
  startup.addEventListener("abort", stoppingStartup, { once: true });
  if (selected.signal?.aborted) abortStartup();
  let opened: z.output<typeof readySchema> | undefined;
  try {
    let pending = Buffer.alloc(0);
    let requested = false;
    for await (const data of child.stdout.iterator({ destroyOnReturn: false })) {
      startup.throwIfAborted();
      if (!Buffer.isBuffer(data) || pending.length + data.length > 8192)
        throw new TnlError("sdk.response_invalid");
      pending = Buffer.concat([pending, data]);
      let newline: number;
      while ((newline = pending.indexOf(10)) !== -1) {
        const record: unknown = JSON.parse(pending.subarray(0, newline).toString("utf8"));
        pending = pending.subarray(newline + 1);
        if (!requested && challengeSchema.safeParse(record).success) {
          requested = true;
          if (selected.enrollment === undefined) throw new TnlError("sdk.publisher_setup_required");
          const key = await bindEnrollment(selected.enrollment, startup)();
          await new Promise<void>((resolve, reject) =>
            child.stdin.write(`${JSON.stringify(key)}\n`, (error) =>
              error ? reject(error) : resolve(),
            ),
          );
          continue;
        }
        const result = readySchema.safeParse(record);
        if (
          !result.success ||
          pending.length !== 0 ||
          (selected.controlUrl !== undefined && result.data.control_url !== selected.controlUrl)
        )
          throw new TnlError("sdk.response_invalid");
        opened = result.data;
        break;
      }
      if (opened !== undefined) break;
    }
    if (opened === undefined) throw new TnlError("sdk.dev_unavailable");
    startup.throwIfAborted();
    const endpoint = parseOwnerEndpoint(opened.endpoint);
    const live = new Set<Publication>();
    const starting = new Set<Promise<Publication>>();
    const cleanups = new Set<() => Promise<void>>();
    let closing: Promise<void> | undefined;
    const close = (): Promise<void> => {
      if (closing !== undefined) return closing;
      const shutdown = new Date(Date.now() + 10_000).toISOString();
      deadline = shutdown;
      closing = Promise.resolve().then(async () => {
        await Promise.allSettled(starting);
        const results = await Promise.allSettled([
          ...Array.from(live, (publication) => publication.close()),
          ...Array.from(cleanups, (cleanup) => cleanup()),
        ]);
        const native = await Promise.allSettled([stopNative()]);
        selected.signal?.removeEventListener("abort", aborted);
        const failures = [...results, ...native].flatMap((result) =>
          result.status === "rejected" ? [result.reason as unknown] : [],
        );
        if (failures.length > 0) throw new AggregateError(failures, "publisher cleanup failed");
      });
      lifetime.abort(new TnlError("sdk.client_closed"));
      return closing;
    };
    const aborted = () => {
      void close().catch(() => {});
    };
    let deadline: string | undefined;
    const handle = Object.freeze({
      publisherIdentityID: opened.publisher_identity_id,
      deploymentID: opened.deployment_id,
      controlUrl: opened.control_url,
      close,
      [Symbol.asyncDispose]: close,
    }) as Publisher;
    owners.set(handle, async (service, target, options = {}) => {
      lifetime.signal.throwIfAborted();
      if (!serviceNameSchema.safeParse(service).success)
        throw new TnlError("sdk.configuration_invalid");
      validatePublicationOptions(options, true);
      if (starting.size + live.size + cleanups.size >= 64)
        throw new TnlError("sdk.client_capacity");
      const signal = AbortSignal.any([
        lifetime.signal,
        ...(options.signal === undefined ? [] : [options.signal]),
      ]);
      const selection: PublicationSelection = {
        kind: "enrolled",
        service,
        environment,
        shutdownDeadline: () => deadline,
        retainCleanup: (cleanup) => cleanups.add(cleanup),
      };
      const runtime = {
        ...nativePublicationRuntime,
        start: async (
          _directory: string,
          _binary: string | undefined,
          facts?: { invocationID?: string | undefined },
          signal?: AbortSignal,
        ) => {
          if (facts?.invocationID === undefined) throw new TnlError("sdk.configuration_invalid");
          return publisherInvocationEndpoint(endpoint, facts.invocationID, signal);
        },
      };
      const work =
        typeof target === "function"
          ? publishFetch(target, { ...options, signal }, runtime, selection)
          : publishServer(target, { ...options, signal }, runtime, selection);
      starting.add(work);
      try {
        const publication = await work;
        live.add(publication);
        void publication.wait().then(
          () => live.delete(publication),
          () => {},
        );
        return publication;
      } finally {
        starting.delete(work);
      }
    });
    selected.signal?.addEventListener("abort", aborted, { once: true });
    if (selected.signal?.aborted) {
      await close();
      selected.signal.throwIfAborted();
    }
    return handle;
  } catch (cause) {
    await stopNative().catch(() => {});
    if (selected.signal?.aborted) selected.signal.throwIfAborted();
    if (cause instanceof TnlError) throw cause;
    throw new TnlError(
      cause instanceof SyntaxError ? "sdk.response_invalid" : "sdk.dev_unavailable",
    );
  } finally {
    startup.removeEventListener("abort", stoppingStartup);
    selected.signal?.removeEventListener("abort", abortStartup);
  }
}
