import { randomBytes } from "node:crypto";
import * as z from "zod";
import { TnlError } from "../../errors.js";
import { parseValue } from "../validation.js";
import { hostnameSchema, httpsOriginSchema, registrationIDSchema } from "../values.js";
import { createPreparedRegistration, type PreparedPublication } from "./app.js";
import {
  newInvocationID,
  startRuntime,
  runtimeRequest,
  type RuntimeEndpoint,
  type EndpointSelection,
} from "./local.js";
import type { ApplicationPublication } from "./publish.js";

const optionsSchema = z.strictObject({
  resource: z
    .templateLiteral([z.enum(["url_", "svc_"]), z.string().regex(/^[A-Za-z0-9]{22}$/)])
    .exactOptional(),
});
export type ApplicationPrepareOptions = z.output<typeof optionsSchema>;
const assignmentSchema = z
  .strictObject({
    version: z.literal(1),
    registration_id: registrationIDSchema,
    resource_id: z.templateLiteral([
      z.enum(["url_", "svc_"]),
      z.string().regex(/^[A-Za-z0-9]{22}$/),
    ]),
    hostname: hostnameSchema,
    public_url: z.union([httpsOriginSchema, z.literal("")]),
  })
  .refine((value) =>
    value.resource_id.startsWith("url_")
      ? value.public_url === `https://${value.hostname}`
      : value.public_url === "" || new URL(value.public_url).hostname === value.hostname,
  );

interface Dependencies {
  start(
    directory: string,
    binary?: string,
    selection?: EndpointSelection,
  ): Promise<RuntimeEndpoint>;
  request(endpoint: RuntimeEndpoint, operation: string, body?: unknown): Promise<unknown>;
}

export function prepareApplicationPublication(
  source: ApplicationPublication,
  directory: string,
  stateDir: string | undefined,
  options: ApplicationPrepareOptions = {},
  dependencies: Dependencies = { start: startRuntime, request: runtimeRequest },
): Promise<PreparedPublication> {
  parseValue(optionsSchema, options, "sdk.configuration_invalid");
  const invocation = newInvocationID();
  const owner = randomBytes(16).toString("hex");
  const request = {
    version: 1,
    invocation_id: invocation,
    owner,
    pid: process.pid,
    server_url: source.server,
    application_credential: source.document,
    resource_id: source.resource,
  };
  return createPreparedRegistration(
    {
      directory,
      owner,
      framework: "node",
      registerOperation: "publications/register",
      ...(source.authorize === undefined ? {} : { authorize: source.authorize }),
      selection: { invocationID: invocation, ...(stateDir === undefined ? {} : { stateDir }) },
      bootstrap: async (endpoint) => {
        await source.authorize?.();
        if (endpoint.scope !== "invocation" || endpoint.invocation_id !== invocation)
          throw new TnlError("sdk.response_invalid");
        const assignment = parseValue(
          assignmentSchema,
          await dependencies.request(endpoint, "publications/prepare", request),
          "sdk.response_invalid",
        );
        if (assignment.resource_id !== source.resource) throw new TnlError("sdk.response_invalid");
        return {
          registrationID: assignment.registration_id,
          service: invocation,
          hostname: assignment.hostname,
          publicURL: assignment.public_url === "" ? undefined : assignment.public_url,
          metadata: {},
        };
      },
    },
    dependencies,
  );
}
