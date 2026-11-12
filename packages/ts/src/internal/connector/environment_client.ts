import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { connect as connectTCP } from "node:net";
import { createInterface } from "node:readline";
import { isDeepStrictEqual } from "node:util";
import * as z from "zod";
import { TnlError } from "../../errors.js";
import type { ServiceFacts } from "../project/service_facts.js";
import { captureServiceFacts } from "../project/service_facts.js";
import { parseValue } from "../validation.js";
import { resolveNativeBinary } from "../native/launcher.js";
import { launchEnvironment } from "../tracing.js";
import { managedFetch } from "./connection.js";
import { environmentOwnerIPC, type EnvironmentOwnerIPC } from "./connection_ipc.js";
import {
  environmentReferenceSchema,
  environmentStatusSchema,
  preparedConnectionSchema,
} from "./contract.js";
import { captureIdentity, type IdentitySource, type OIDCAssertion } from "../identity/source.js";
import { identitySourceChallengeSchema } from "../identity/validation.js";
import type { IdentitySourceReply, IdentitySourceVisitorSelection } from "../identity/models.gen.js";
import {
  clientFromSelection,
  type SelectedClient,
  type ResolvedService,
} from "./selected_client.js";

export type EnvironmentReference = z.infer<typeof environmentReferenceSchema>;
export type { IdentitySource, OIDCAssertion, NativeAcquisition } from "../identity/source.js";
export type { IdentitySourceChallenge, IdentitySourceReply, IdentitySourceSelection } from "../identity/models.gen.js";
export interface EnvironmentClientOptions<Services extends ServiceFacts> {
  readonly services: Services;
  readonly environment: EnvironmentReference;
  readonly identity: IdentitySource & { readonly permission_id: string };
}

type Status = z.infer<typeof environmentStatusSchema>;
interface NativeOwner {
  child: ChildProcessWithoutNullStreams;
  exited: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
  ipc?: EnvironmentOwnerIPC;
  status?: Status;
  stopped: boolean;
  exit?: { code: number | null; signal: NodeJS.Signals | null };
  publicKey?: string;
  sessionID?: string;
  preparing?: Promise<void>;
  cleanupConfirmed?: boolean;
}
interface Resolution extends ResolvedService {
  readonly owner: NativeOwner;
  readonly status: Status;
  initial: boolean;
}

function invalid(): TnlError {
  return new TnlError("sdk.response_invalid");
}

// this adapter consumes the native contract, not manager-only environment GET.
// every owner admits only its one exact requested service and keeps its own key.
export function environmentClient<const Services extends ServiceFacts>(
  options: EnvironmentClientOptions<Services>,
): SelectedClient<Services> {
  const facts = captureServiceFacts(options.services);
  const environment = parseValue(
    environmentReferenceSchema,
    options.environment,
    "sdk.configuration_invalid",
  );
  const source = options.identity;
  const identity = captureIdentity(source);
  if (!/^mwp_[A-Za-z0-9]{22}$/.test(source.permission_id))
    throw new TnlError("sdk.configuration_invalid");
  const permission = source.permission_id;
  // capture the callback once, retaining its private source receiver. selection
  // fields are already captured above and never resampled from that receiver.
  const assertion = identity.assertion;
  const owners = new Set<NativeOwner>();
  const starts = new Map<string, Promise<Resolution>>();
  const fetches = new Map<string, ReturnType<typeof managedFetch>>();
  const transports = new Map<string, Resolution>();
  const sources = new Set<Promise<OIDCAssertion>>();
  const abandoned = new Map<Promise<OIDCAssertion>, AbortSignal>();
  const sourceFailures = new Set<unknown>();
  let closed = false;

  async function boundedWait<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
    signal.throwIfAborted();
    return new Promise<T>((resolve, reject) => {
      const abort = () => reject(signal.reason);
      signal.addEventListener("abort", abort, { once: true });
      void work.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
    });
  }

  async function join(owner: NativeOwner) {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([owner.exited, new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => { owner.child.kill("SIGKILL"); reject(new TnlError("sdk.connection_unavailable")); }, 20_000);
      })]);
    } catch (error) {
      owner.child.kill("SIGKILL");
      await owner.exited;
      throw error;
    } finally { clearTimeout(timer); }
  }

  async function proof(
    raw: unknown,
    operation: "visitor_prepare" | "visitor_attach",
    selection: IdentitySourceVisitorSelection,
    owner: NativeOwner,
    signal: AbortSignal,
  ): Promise<IdentitySourceReply> {
    const challenge = identitySourceChallengeSchema.parse(raw);
    const audience =
      operation === "visitor_prepare"
        ? `${environment.server}/v1/projects/${environment.project_key}/environments/${environment.environment_id}/visitors/prepare`
        : `${environment.server}/v1/environment-visitor-sessions/`;
    if (
      challenge.operation !== operation ||
      challenge.server !== environment.server ||
      !isDeepStrictEqual(challenge.source, identity.selector) ||
      Date.parse(challenge.expires_at) <= Date.now() || Date.parse(challenge.expires_at) > Date.now() + 60_000 ||
      owner.publicKey !== undefined && owner.publicKey !== challenge.native_public_key ||
      owner.sessionID !== undefined && owner.sessionID !== challenge.session_id ||
      !isDeepStrictEqual(challenge.selection, selection) ||
      (operation === "visitor_prepare"
        ? challenge.audience !== audience
        : !challenge.audience.startsWith(audience) ||
          !/^wls_[A-Za-z0-9]{22}\/assertions$/.test(challenge.audience.slice(audience.length)))
    )
      throw invalid();
    owner.publicKey = challenge.native_public_key;
    if (challenge.session_id !== undefined) owner.sessionID = challenge.session_id;
    // a deadline cancels the wait as well as the source's cooperative work.
    const bounded = AbortSignal.any([signal, AbortSignal.timeout(Math.max(1, Math.min(10_000, Date.parse(challenge.expires_at) - Date.now())))]);
    bounded.throwIfAborted();
    if (sources.size >= 64 || sourceFailures.size >= 64) throw new TnlError("sdk.connection_unavailable");
    if (assertion === undefined) throw invalid();
    const call = Promise.resolve().then(() => assertion(bounded));
    sources.add(call);
    void call.then(() => {}, (error: unknown) => {
      const signal = abandoned.get(call);
      if (signal !== undefined && error !== signal.reason) sourceFailures.add(error);
    }).finally(() => { sources.delete(call); abandoned.delete(call); });
    let value: OIDCAssertion;
    try { value = await boundedWait(call, bounded); }
    catch (error) {
      if (bounded.aborted) {
        abandoned.set(call, bounded);
        void call.catch((late: unknown) => { if (late !== bounded.reason) sourceFailures.add(late); }).finally(() => abandoned.delete(call));
      }
      throw error;
    }
    bounded.throwIfAborted();
    if (
      value.expiresAt.getTime() <= Date.now()
    )
      throw new TnlError("sdk.workload_assertion_unavailable");
    return { schema: 1, challenge_id: challenge.id, assertion: value.token };
  }

  async function start(service: string, signal: AbortSignal): Promise<Resolution> {
    if (closed || owners.size >= 32) throw new TnlError("sdk.connection_unavailable");
    const fact = facts[service];
    if (fact === undefined) throw new TnlError("sdk.configuration_invalid");
    const selection = {
      environment,
      permission_id: permission,
      services: { [service]: fact.protocol },
    };
    const binary = resolveNativeBinary();
    const childEnvironment = { ...launchEnvironment() };
    for (const key of ["ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "VERCEL_OIDC_TOKEN", "VERCEL_OIDC_TOKEN_FILE", "VERCEL_TOKEN"]) delete childEnvironment[key];
    if ("acquisition" in identity.startup && identity.startup.acquisition.method === "token-env") delete childEnvironment[identity.startup.acquisition.token_env];
    const child = spawn(
      binary,
      [
        "--no-telemetry",
        "runtime",
        "connections",
        "environment-serve",
        "--parent-pid",
        String(process.pid),
      ],
      { stdio: "pipe", env: childEnvironment },
    );
    const owner: NativeOwner = {
      child,
      stopped: false,
      exited: new Promise((resolve, reject) => {
        child.once("error", () => reject(new TnlError("sdk.connection_unavailable")));
        child.once("close", (code, childSignal) => resolve({ code, signal: childSignal }));
      }),
    };
    void owner.exited.catch(() => {});
    void owner.exited.then((exit) => { owner.exit = exit; }, () => {});
    owners.add(owner);
    const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
    const iterator = lines[Symbol.asyncIterator]();
    let bytes = 0;
    child.stdout.on("data", (data: Buffer) => {
      bytes += data.length;
      if (bytes > 128 * 1024) child.kill("SIGTERM");
    });
    child.stderr.resume();
    child.stdin.on("error", () => {});
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(40_000)]);
    const abort = () => child.kill("SIGTERM");
    deadline.addEventListener("abort", abort, { once: true });
    const line = async (): Promise<unknown> => {
      const result = await iterator.next();
      deadline.throwIfAborted();
      if (result.done || bytes > 128 * 1024) throw new TnlError("sdk.connection_unavailable");
      const value: unknown = JSON.parse(result.value);
      return value;
    };
    try {
      deadline.throwIfAborted();
      child.stdin.write(JSON.stringify({ schema: 1, selection, ...identity.startup, ...(identity.environment === undefined ? {} : { source_environment: identity.environment() }) }) + "\n");
      if (assertion !== undefined) {
        const reply = await proof(await line(), "visitor_prepare", selection, owner, deadline);
        child.stdin.end(JSON.stringify(reply) + "\n");
      } else child.stdin.end();
      const rawStatus = await line();
      const failed = z.strictObject({ schema: z.literal(1), state: z.literal("failed"), pid: z.number().int(), executable: z.string(), reason: z.string(), cleanup_complete: z.boolean().optional(), expires_at: z.unknown().optional(), project_runtime: z.unknown().optional(), connection_handle: z.unknown().optional() }).safeParse(rawStatus);
      if (failed.success && failed.data.pid === child.pid && failed.data.executable === binary) {
        owner.cleanupConfirmed = failed.data.cleanup_complete === true;
        throw new TnlError("sdk.connection_unavailable");
      }
      const status = environmentStatusSchema.parse(rawStatus);
      if (
        status.pid !== child.pid ||
        status.executable !== binary ||
        !isDeepStrictEqual(status.environment.environment, environment) ||
        Object.keys(status.environment.services).length !== 1 ||
        status.environment.services[service]?.protocol !== fact.protocol
      )
        throw invalid();
      owner.status = status;
      owner.ipc = await environmentOwnerIPC(status.connection_handle);
      deadline.throwIfAborted();
      return { service, protocol: fact.protocol, owner, status, initial: true };
    } catch (error) {
      child.kill("SIGTERM");
      const exit = await join(owner).catch((cleanup: unknown) => {
        throw new AggregateError([error, cleanup], "environment startup and cleanup failed");
      });
      owner.stopped = exit.code === 0 || owner.cleanupConfirmed === true;
      if (owner.stopped) {
        owners.delete(owner);
      }
      // never report cancellation as proof that independent native cleanup worked.
      if (deadline.aborted && error === deadline.reason && exit.code !== 0)
        throw new AggregateError([error, new TnlError("sdk.connection_unavailable")], "environment startup and cleanup failed");
      throw error;
    } finally {
      deadline.removeEventListener("abort", abort);
      lines.close();
    }
  }

  async function prepareOwned(resolution: Resolution, signal: AbortSignal) {
    const { owner, status, service } = resolution;
    const ipc = owner.ipc;
    if (ipc === undefined || owner.stopped || !owners.has(owner)) throw invalid();
    const selection = {
      environment,
      permission_id: permission,
      services: { [service]: resolution.protocol },
    };
    const initial = resolution.initial;
    resolution.initial = false;
    const reply = initial || assertion === undefined ? undefined : await proof(await ipc.challenge(), "visitor_attach", selection, owner, signal);
    const response = await ipc.prepareIdentity(service, reply, initial ? undefined : identity.environment?.());
    const raw = preparedConnectionSchema.parse(response);
    signal.throwIfAborted();
    if (
      !isDeepStrictEqual(raw.environment, status.environment) ||
      raw.connection.protocol !== resolution.protocol
    )
      throw invalid();
    const endpoint = status.environment.services[service]?.endpoint;
    const metadata = raw.project_runtime.services[service];
    if (
      endpoint === undefined ||
      metadata === undefined ||
      metadata.hostname !== endpoint.hostname ||
      metadata.port !== endpoint.port ||
      metadata.protocol !== resolution.protocol
    )
      throw invalid();
    transports.set(raw.connection.transportID, resolution);
    return {
      wire: z.object({ connection: z.unknown() }).parse(response).connection,
      snapshot: raw.connection,
    };
  }

  async function prepare(resolution: Resolution, signal: AbortSignal) {
    const owner = resolution.owner;
    const previous = owner.preparing ?? Promise.resolve();
    let release!: () => void;
    owner.preparing = new Promise<void>((resolve) => { release = resolve; });
    try {
      await previous;
      signal.throwIfAborted();
      return await prepareOwned(resolution, signal);
    } finally { release(); }
  }

  return clientFromSelection(facts, {
    resolve(service, signal) {
      let pending = starts.get(service);
      if (pending === undefined) {
        pending = start(service, signal);
        starts.set(service, pending);
      }
      return pending;
    },
    async prepare(resolution, signal) {
      return (await prepare(resolution, signal)).wire;
    },
    http(snapshot) {
      const selected = transports.get(snapshot.transportID);
      if (selected === undefined) throw invalid();
      const key = JSON.stringify([selected.service, snapshot.transportID]);
      const current = fetches.get(key);
      if (current !== undefined) return current;
      if (fetches.size >= 32) throw new TnlError("sdk.connection_unavailable");
      const fetch = managedFetch(snapshot.url, async (signal) => {
        return (await prepare(selected, signal ?? new AbortController().signal)).snapshot;
      });
      fetches.set(key, fetch);
      return fetch;
    },
    mysql(snapshot) {
      return () => connectTCP({ host: snapshot.host, port: snapshot.port });
    },
    async close() {
      closed = true;
      const failures: unknown[] = [];
      for (const result of await Promise.allSettled(
        [...fetches.values()].map((fetch) => fetch.close()),
      ))
        if (result.status === "rejected") failures.push(result.reason);
      for (const owner of owners) {
        if (owner.stopped) continue;
        try {
          if (owner.exit === undefined) {
            if (owner.ipc !== undefined) await owner.ipc.stop();
            else owner.child.kill("SIGTERM");
          }
          const exit = await join(owner);
          if (exit.code !== 0) throw new TnlError("sdk.connection_unavailable");
          owner.ipc?.close();
          owner.stopped = true;
        } catch (error) {
          failures.push(error);
        }
      }
      try { await boundedWait(Promise.allSettled([...sources]), AbortSignal.timeout(10_000)); }
      catch (error) { failures.push(error); }
      failures.push(...sourceFailures);
      if (failures.length) throw new AggregateError(failures, "environment client cleanup failed");
    },
  });
}
