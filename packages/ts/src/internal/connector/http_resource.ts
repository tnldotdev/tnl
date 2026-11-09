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
import { applicationHTTP } from "./application_http.js";
import { credentialSchema } from "./http_credential.js";
import { cancellable } from "./cancellation.js";
import type { TnlApplicationCredential, TnlApplicationResource } from "../../credential.js";

export function httpResources(credential: string | TnlApplicationCredential) {
  const selected =
    typeof credential === "string"
      ? parseValue(credentialSchema, credential, "sdk.configuration_invalid")
      : undefined;
  const setup = new AbortController();
  const application =
    typeof credential === "string" ? undefined : applicationHTTP(credential, setup.signal);
  const lifetime = new AbortController();
  const connections = new Map<string, TnlHTTPConnection>();
  const clients = new Set<{ close(): Promise<void> }>();
  const pending = new Set<Promise<Response>>();
  let closed = false;
  let closing: Promise<void> | undefined;
  const check = () => {
    if (closed) throw new TnlError("sdk.client_closed");
  };
  const connection = (
    url: `https://${string}`,
    key: string,
    authorize: (signal: AbortSignal) => Promise<string>,
  ): TnlHTTPConnection => {
    check();
    const existing = connections.get(key);
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
          request.headers.set(
            "Tnl-Visitor-Token",
            await cancellable(signal, () => authorize(signal)),
          );
          signal.throwIfAborted();
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
    connections.set(key, connection);
    return connection;
  };
  const acquire = async (
    resource: string,
  ): Promise<{ key: string; connection: TnlHTTPConnection }> => {
    check();
    if (application === undefined) {
      const url = parseValue(httpsOriginSchema, resource, "sdk.configuration_invalid");
      const token = selected;
      if (token === undefined) throw new TnlError("sdk.credential_denied");
      return { key: url, connection: connection(url, url, async () => token) };
    }
    const id = resource as TnlApplicationResource;
    const prepared = await application.resolve(id);
    check();
    return {
      key: prepared.key,
      connection: connection(prepared.url, prepared.key, async (signal) => {
        signal.throwIfAborted();
        const current = await application.resolve(id);
        signal.throwIfAborted();
        if (current.key !== prepared.key) throw new TnlError("sdk.credential_denied");
        return current.credential;
      }),
    };
  };
  function connect(resource: `https://${string}`): TnlHTTPConnection;
  function connect(resource: TnlApplicationResource): Promise<TnlHTTPConnection>;
  function connect(resource: string): TnlHTTPConnection | Promise<TnlHTTPConnection> {
    check();
    if (application !== undefined) return acquire(resource).then((selected) => selected.connection);
    const url = parseValue(httpsOriginSchema, resource, "sdk.configuration_invalid");
    const token = selected;
    if (token === undefined) throw new TnlError("sdk.credential_denied");
    return connection(url, url, async () => token);
  }
  const fence = () => {
    closed = true;
    setup.abort(new TnlError("sdk.client_closed"));
  };
  return {
    controlURL: application?.controlURL,
    connect,
    client<Client>(
      resource: `https://${string}` | TnlApplicationResource,
      options: TnlClientOptions<TnlHTTPConnection, Client>,
    ): TnlClientFactory<Client> {
      check();
      // validate constant-token origins eagerly, retaining the synchronous form.
      if (application === undefined) connect(resource as `https://${string}`);
      const factory = clientFactory(
        () => acquire(resource),
        options,
        () => !closed,
      );
      clients.add(factory);
      return factory;
    },
    fence,
    close(): Promise<void> {
      fence();
      if (closing !== undefined) return closing;
      closing = (async () => {
        const results = await Promise.allSettled([...clients].map((client) => client.close()));
        const failures = results.flatMap((result) =>
          result.status === "rejected" ? [result.reason as unknown] : [],
        );
        await application?.finished();
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
