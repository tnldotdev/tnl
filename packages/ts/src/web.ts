import * as z from "zod";
import type { TnlClientFactory, TnlClientOptions, TnlHTTPConnection } from "./client.js";
import { httpResources, credentialSchema } from "./internal/connector/http_resource.js";
import { parseValue } from "./internal/validation.js";
export { TnlError, type TnlErrorCode } from "./errors.js";
export type { TnlClientFactory, TnlClientOptions, TnlFetch, TnlHTTPConnection } from "./client.js";

export type TnlOptions = Readonly<{ credential: string }>;
export interface TnlInstance {
  connect(resource: `https://${string}`): TnlHTTPConnection;
  client<Client>(
    resource: `https://${string}`,
    options: TnlClientOptions<TnlHTTPConnection, Client>,
  ): TnlClientFactory<Client>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

/** server-side Fetch runtimes; never import this credential into browser code. */
export function createTnl(options: TnlOptions): TnlInstance {
  const selected = parseValue(
    z.strictObject({ credential: credentialSchema }),
    options,
    "sdk.configuration_invalid",
  );
  const resources = httpResources(selected.credential);
  return Object.freeze({
    connect: resources.connect,
    client: resources.client,
    close: resources.close,
    [Symbol.asyncDispose]: resources.close,
  });
}
