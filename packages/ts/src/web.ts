import * as z from "zod";
import type { TnlHTTPInstance } from "./client.js";
import type { TnlApplicationCredential, TnlApplicationResource } from "./credential.js";
import { httpResources } from "./internal/connector/http_resource.js";
import { credentialSchema } from "./internal/connector/http_credential.js";
import { applicationCredentialSchema } from "./internal/connector/application_http.js";
import { parseValue } from "./internal/validation.js";
export { TnlError, type TnlErrorCode } from "./errors.js";
export type { TnlClientFactory, TnlClientOptions, TnlFetch, TnlHTTPConnection } from "./client.js";
export type {
  TnlApplicationCredential,
  TnlApplicationGrant,
  TnlApplicationResource,
} from "./credential.js";

export type TnlOptions = Readonly<{ credential: string | TnlApplicationCredential }>;
export type TnlInstance<
  Resource extends `https://${string}` | TnlApplicationResource =
    | `https://${string}`
    | TnlApplicationResource,
> = TnlHTTPInstance<Resource>;

/** server-side Fetch runtimes; never import this credential into browser code. */
export function createTnl<Credential extends TnlOptions["credential"]>(
  options: Readonly<{ credential: Credential }>,
): TnlInstance<Credential extends string ? `https://${string}` : TnlApplicationResource> {
  const selected = parseValue(
    z.strictObject({ credential: z.union([credentialSchema, applicationCredentialSchema]) }),
    options,
    "sdk.configuration_invalid",
  );
  const resources = httpResources(selected.credential);
  return Object.freeze({
    connect: resources.connect,
    client: resources.client,
    close: resources.close,
    [Symbol.asyncDispose]: resources.close,
  }) as TnlInstance<Credential extends string ? `https://${string}` : TnlApplicationResource>;
}
