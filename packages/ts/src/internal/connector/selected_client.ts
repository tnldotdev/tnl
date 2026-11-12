import { TnlError } from "../../errors.js";
import type { TnlConnectionRegistry } from "../../project.js";
import { captureServiceFacts, type ServiceFacts } from "../project/service_facts.js";
import { isServiceName } from "../values.js";
import { decodeSettings, settingsDecoders, type SettingsTransports } from "./settings.js";

export interface ResolvedService {
  readonly service: string;
  readonly protocol: keyof TnlConnectionRegistry;
}

// the native adapter owns an exact environment and explicit identity source.
// it supplies current validated resolution facts and rechecks them at prepare.
// this is a consumer-owned operation interface, not another HTTP/IPC contract.
export interface ServiceSelection<Resolution extends ResolvedService> extends SettingsTransports {
  resolve(service: string, signal: AbortSignal): Promise<Resolution>;
  prepare(resolution: Resolution, signal: AbortSignal): Promise<unknown>;
  close(): Promise<void>;
}

export interface SelectedClient<Services extends ServiceFacts> {
  connect<Name extends Extract<keyof Services, string>>(
    name: Name,
  ): Promise<TnlConnectionRegistry[Services[Name]["protocol"]]>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

// the normal SDK's native consumer will construct this client after the source
// contract is wired. no public identity/discovery format is invented here.
export function clientFromSelection<
  const Services extends ServiceFacts,
  Resolution extends ResolvedService,
>(services: Services, selection: ServiceSelection<Resolution>): SelectedClient<Services> {
  const owned = captureServiceFacts(services);
  const lifetime = new AbortController();
  const stopped = new TnlError("sdk.connection_unavailable");
  const pending = new Set<Promise<unknown>>();
  const terminal = new Set<unknown>();
  let closed = false;
  let cleaned = false;
  let closing: Promise<void> | undefined;
  const decoders = settingsDecoders({
    http(snapshot) {
      const dispatch = selection.http(snapshot);
      return async (input, init) => {
        if (closed) throw stopped;
        const sourceSignal = init?.signal ?? (input instanceof Request ? input.signal : undefined);
        const signal =
          sourceSignal === undefined
            ? lifetime.signal
            : AbortSignal.any([lifetime.signal, sourceSignal]);
        return dispatch(input, { ...init, signal });
      };
    },
    mysql(snapshot) {
      const stream = selection.mysql(snapshot);
      return () => {
        if (closed) throw stopped;
        return stream();
      };
    },
  });

  async function prepare<Name extends Extract<keyof Services, string>>(
    name: Name,
  ): Promise<TnlConnectionRegistry[Services[Name]["protocol"]]> {
    if (closed) throw stopped;
    if (pending.size >= 64) throw new TnlError("sdk.connection_unavailable");
    if (!isServiceName(name)) throw new TnlError("sdk.configuration_invalid");
    const fact = Object.hasOwn(owned, name) ? owned[name] : undefined;
    if (fact === undefined) throw new TnlError("sdk.configuration_invalid");
    const protocol: Services[Name]["protocol"] = fact.protocol;
    const resolution = await selection.resolve(name, lifetime.signal);
    if (closed) throw stopped;
    if (resolution.service !== name || resolution.protocol !== protocol)
      throw new TnlError("sdk.response_invalid");
    const raw = await selection.prepare(resolution, lifetime.signal);
    if (closed) throw stopped;
    return decodeSettings(decoders, protocol, raw);
  }

  function connect<Name extends Extract<keyof Services, string>>(
    name: Name,
  ): Promise<TnlConnectionRegistry[Services[Name]["protocol"]]> {
    const work = prepare(name);
    pending.add(work);
    void work.finally(() => pending.delete(work)).catch(() => {});
    return work;
  }

  async function finishClose(): Promise<void> {
    for (const result of await Promise.allSettled(pending))
      if (result.status === "rejected" && result.reason !== stopped) terminal.add(result.reason);
    let cleanup: unknown;
    let cleanupFailed = false;
    if (!cleaned) {
      try {
        await selection.close();
        cleaned = true;
      } catch (error) {
        cleanupFailed = true;
        cleanup = error;
      }
    }
    const failures = [...terminal, ...(cleanupFailed ? [cleanup] : [])];
    if (failures.length === 1) throw failures[0];
    if (failures.length > 1)
      throw new AggregateError(failures, "environment client cleanup failed");
  }

  function close(): Promise<void> {
    closed = true;
    lifetime.abort(stopped);
    closing ??= finishClose().catch((error: unknown) => {
      closing = undefined;
      throw error;
    });
    return closing;
  }

  return Object.freeze({ connect, close, [Symbol.asyncDispose]: close });
}
