import * as z from "zod";
import type {
  TnlClientFactory,
  TnlClientOptions,
  TnlFetch,
  TnlHTTPConnection,
} from "../../client.js";
import { TnlError, privateTnlError } from "../../errors.js";
import { parseValue } from "../validation.js";
import { httpsOriginSchema } from "../values.js";
import { clientFactory } from "./client_factory.js";

export const credentialSchema = z
  .string()
  .min(1)
  .max(2048)
  .refine((value) => {
    const parts = value.split(".");
    if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part))) return false;
    if (parts[0] === "vsh1" || parts[0] === "vsg1") {
      const prefix = parts[0] === "vsh1" ? "shr_" : "shg_";
      if (!new RegExp(`^${prefix}[A-Za-z0-9]{22}$`).test(parts[1] ?? "") || parts[2]?.length !== 43)
        return false;
      try {
        const secret = parts[2].replaceAll("-", "+").replaceAll("_", "/");
        return atob(secret).length === 32 && btoa(atob(secret)).replaceAll("=", "") === secret;
      } catch {
        return false;
      }
    }
    // signed visitor permissions are opaque here; only the publisher verifies them.
    return parts[0]?.startsWith("ey") === true;
  });

export function httpResources(credential: string) {
  const selected = parseValue(credentialSchema, credential, "sdk.configuration_invalid");
  const lifetime = new AbortController();
  const connections = new Map<string, TnlHTTPConnection>();
  const clients = new Set<{ close(): Promise<void> }>();
  const pending = new Set<Promise<Response>>();
  let closed = false;
  let closing: Promise<void> | undefined;
  const check = () => {
    if (closed) throw new TnlError("sdk.client_closed");
  };
  const connect = (resource: `https://${string}`): TnlHTTPConnection => {
    check();
    const url = parseValue(httpsOriginSchema, resource, "sdk.configuration_invalid");
    const existing = connections.get(url);
    if (existing !== undefined) return existing;
    if (connections.size >= 64) throw new TnlError("sdk.client_capacity");
    const fetch: TnlFetch = (input, init) => {
      if (closed) return Promise.reject(new TnlError("sdk.client_closed"));
      const operation = Promise.resolve().then(async () => {
        check();
        let request: Request;
        try {
          request = new Request(
            input instanceof Request ? input : new URL(String(input), `${url}/`),
            {
              ...init,
              ...(init?.body instanceof ReadableStream ? { duplex: "half" } : {}),
            },
          );
        } catch (cause) {
          throw privateTnlError("sdk.configuration_invalid", cause);
        }
        const signal = AbortSignal.any([request.signal, lifetime.signal]);
        // one explicit origin, one credential, one dispatch. never replay a body
        // or let a redirect or ambient browser sign-in replace this selection.
        try {
          if (
            new URL(request.url).origin !== url ||
            ["Tnl-Visitor-Token", "Tnl-Access-Token", "Tnl-Share-Token"].some((header) =>
              request.headers.has(header),
            )
          )
            throw new TnlError("sdk.configuration_invalid");
          signal.throwIfAborted();
          request.headers.set("Tnl-Visitor-Token", selected);
          let response: Response;
          try {
            response = await globalThis.fetch(request, {
              signal,
              redirect: "manual",
              credentials: "omit",
            });
          } catch (cause) {
            if (signal.aborted) throw signal.reason;
            throw privateTnlError("sdk.http_unavailable", cause);
          }
          if (signal.aborted) {
            await response.body?.cancel().catch(() => {});
            signal.throwIfAborted();
          }
          return response;
        } catch (cause) {
          // validation and pre-dispatch cancellation still own the upload.
          if (request.body !== null && !request.body.locked)
            void request.body.cancel(cause).catch(() => {});
          throw cause;
        }
      });
      pending.add(operation);
      void operation.then(
        () => pending.delete(operation),
        () => pending.delete(operation),
      );
      return operation;
    };
    const connection = Object.freeze({ url, fetch });
    connections.set(url, connection);
    return connection;
  };
  return {
    connect,
    client<Client>(
      resource: `https://${string}`,
      options: TnlClientOptions<TnlHTTPConnection, Client>,
    ): TnlClientFactory<Client> {
      check();
      const connection = connect(resource);
      const factory = clientFactory(
        async () => {
          check();
          return { key: connection.url, connection };
        },
        options,
        () => !closed,
      );
      clients.add(factory);
      return factory;
    },
    fence() {
      closed = true;
    },
    close(): Promise<void> {
      closed = true;
      if (closing !== undefined) return closing;
      closing = (async () => {
        const results = await Promise.allSettled([...clients].map((client) => client.close()));
        const failures = results.flatMap((result) =>
          result.status === "rejected" ? [result.reason as unknown] : [],
        );
        if (failures.length > 0) throw new AggregateError(failures, "HTTP client cleanup failed");
        lifetime.abort(new TnlError("sdk.client_closed"));
        await Promise.allSettled(pending);
        clients.clear();
        connections.clear();
      })().catch((cause: unknown) => {
        closing = undefined;
        throw cause;
      });
      return closing;
    },
  };
}
