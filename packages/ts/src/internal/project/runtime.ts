import * as z from "zod";
import { TnlError } from "../../errors.js";
import { parseValue } from "../validation.js";
import {
  hostnameSchema,
  httpsOriginSchema,
  portSchema,
  protocolSchema,
  serviceNameSchema,
} from "../values.js";

const maximumRuntimeBytes = 64 * 1024;
const labelSchema = hostnameSchema.refine((value) => !value.includes("."));
const worktreeLabelSchema = z
  .strictObject({
    project: labelSchema,
    checkout: labelSchema.exactOptional(),
    id: labelSchema,
    fullLabel: labelSchema,
  })
  .refine(
    ({ project, checkout, id, fullLabel }) =>
      fullLabel === [project, checkout, id].filter((part) => part !== undefined).join("-"),
  )
  .readonly();

const mountPrefixSchema = z.templateLiteral(["/", z.string()]).refine(
  (prefix) =>
    prefix.length >= 2 &&
    prefix.length <= 256 &&
    !prefix.endsWith("/") &&
    prefix !== "/__tnl" &&
    !prefix.startsWith("/__tnl/") &&
    prefix
      .slice(1)
      .split("/")
      .every(
        (segment) => segment !== "." && segment !== ".." && /^[A-Za-z0-9._~-]+$/.test(segment),
      ),
);

// lookups may miss even when consumers disable noUncheckedIndexedAccess.
function metadataMap<K extends z.ZodType<string>, V extends z.ZodType>(key: K, value: V) {
  return z
    .record(key, value)
    .refine((entries) => Object.keys(entries).length <= 32)
    .transform((entries): Readonly<Record<string, z.output<V> | undefined>> =>
      Object.freeze(Object.assign(Object.create(null), entries)),
    );
}

const pathMetadataSchema = z
  .strictObject({
    service: serviceNameSchema,
    url: z.templateLiteral(["https://", z.string()]),
    stripPrefix: z.boolean(),
  })
  .readonly();
const address = {
  namespace: hostnameSchema,
  hostname: hostnameSchema,
  port: portSchema,
  public: z.boolean(),
};
const httpServiceMetadataSchema = z.strictObject({
  protocol: z.literal("http"),
  ...address,
  url: httpsOriginSchema,
  paths: metadataMap(mountPrefixSchema, pathMetadataSchema).optional(),
});
const serviceMetadataSchema = z
  .discriminatedUnion("protocol", [
    httpServiceMetadataSchema,
    z.strictObject({ protocol: z.literal("kubernetes"), ...address, url: httpsOriginSchema }),
    z.strictObject({ protocol: z.literal("postgres"), ...address }),
    z.strictObject({ protocol: z.literal("mysql"), ...address }),
    z.strictObject({ protocol: z.literal("tcp"), ...address }),
  ])
  .refine(
    (service) =>
      !("url" in service) ||
      service.url ===
        `https://${service.hostname}${service.port === 443 ? "" : `:${service.port}`}`,
  )
  .readonly();

const integrationOriginSchema = z
  .strictObject({ hostname: hostnameSchema, url: httpsOriginSchema })
  .refine(({ hostname, url }) => url === `https://${hostname}`)
  .readonly();
const webhookMethodSchema = z.enum(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]);
const webhookSchema = z
  .strictObject({
    hostname: hostnameSchema,
    url: z.templateLiteral(["https://", z.string()]),
    service: z.union([serviceNameSchema, z.literal("")]),
    path: mountPrefixSchema,
    methods: z
      .array(webhookMethodSchema)
      .min(1)
      .max(7)
      .refine((methods) => new Set(methods).size === methods.length)
      .readonly(),
  })
  .refine(({ hostname, path, url }) => url === `https://${hostname}${path}`)
  .readonly();
const aliasSchema = z
  .strictObject({ hostname: hostnameSchema, url: httpsOriginSchema, service: serviceNameSchema })
  .refine(({ hostname, url }) => url === `https://${hostname}`)
  .readonly();

const projectFields = {
  namespace: z.union([hostnameSchema, z.literal("")]),
  services: metadataMap(serviceNameSchema, serviceMetadataSchema),
  worktree: z.strictObject({ label: worktreeLabelSchema }).readonly().optional(),
  oauth: integrationOriginSchema.optional(),
  webhooks: metadataMap(serviceNameSchema, webhookSchema).optional(),
  aliases: metadataMap(serviceNameSchema, aliasSchema).optional(),
};

function validProject(project: z.output<z.ZodObject<typeof projectFields>>): boolean {
  const { services, namespace, oauth, webhooks, aliases } = project;
  if (
    namespace === "" &&
    (Object.keys(services).length !== 0 ||
      oauth !== undefined ||
      webhooks !== undefined ||
      aliases !== undefined)
  )
    return false;
  const hostnames = new Set<string>();
  for (const [name, service] of Object.entries(services)) {
    if (service === undefined || hostnames.has(service.hostname)) return false;
    hostnames.add(service.hostname);
    if (service.protocol === "http" && service.paths !== undefined) {
      for (const [prefix, mount] of Object.entries(service.paths)) {
        if (
          mount === undefined ||
          mount.service === name ||
          mount.url !== `${service.url}${prefix}`
        )
          return false;
      }
    }
  }
  for (const endpoint of Object.values(webhooks ?? {})) {
    if (
      endpoint === undefined ||
      (!(endpoint.service === "" && Object.keys(services).length === 0) &&
        services[endpoint.service]?.protocol !== "http")
    )
      return false;
  }
  for (const alias of Object.values(aliases ?? {})) {
    if (
      alias === undefined ||
      services[alias.service]?.protocol !== "http" ||
      hostnames.has(alias.hostname)
    )
      return false;
    hostnames.add(alias.hostname);
  }
  return true;
}

export const projectMetadataSchema = z.strictObject(projectFields).refine(validProject).readonly();
export const projectRuntimeSchema = z
  .strictObject({ ...projectFields, dev: z.boolean() })
  .refine(validProject)
  .readonly();
export type ServiceProtocol = z.output<typeof protocolSchema>;
export type ProjectServiceMetadata = z.output<typeof serviceMetadataSchema>;
export type HTTPServiceMetadata = Extract<ProjectServiceMetadata, { protocol: "http" }>;
export type ProjectPathMetadata = z.output<typeof pathMetadataSchema>;
export type ProjectMetadata = z.output<typeof projectMetadataSchema>;
export type ProjectRuntime = z.output<typeof projectRuntimeSchema>;
export type WorktreeLabel = z.output<typeof worktreeLabelSchema>;
export type IntegrationOrigin = z.output<typeof integrationOriginSchema>;
export type WebhookMetadata = z.output<typeof webhookSchema>;
export type WebhookMethod = z.output<typeof webhookMethodSchema>;
export type AliasMetadata = z.output<typeof aliasSchema>;

export function parseProjectMetadata(value: unknown): ProjectMetadata {
  return parseValue(projectMetadataSchema, value, "sdk.runtime_invalid");
}
export function parseProjectRuntime(value: unknown): ProjectRuntime {
  return parseValue(projectRuntimeSchema, value, "sdk.runtime_invalid");
}

/** returns the public hostnames that can reach this service. */
export function serviceHostnames(assignment: {
  readonly hostname: string | undefined;
  readonly service: string;
  readonly project: ProjectRuntime;
}): string[] {
  const hostnames = new Set(assignment.hostname === undefined ? [] : [assignment.hostname]);
  for (const alias of Object.values(assignment.project.aliases ?? {})) {
    if (alias === undefined) continue;
    const service = assignment.project.services[alias.service];
    if (
      alias.service === assignment.service ||
      (service?.protocol === "http" &&
        Object.values(service.paths ?? {}).some((mount) => mount?.service === assignment.service))
    ) {
      hostnames.add(alias.hostname);
    }
  }
  return [...hostnames];
}

export function parseRuntimePayload(serialized: string | undefined): ProjectRuntime | undefined {
  if (serialized === undefined) return undefined;
  if (byteLength(serialized) > maximumRuntimeBytes) throw new TnlError("sdk.runtime_invalid");
  let value: unknown;
  try {
    value = JSON.parse(serialized);
  } catch (cause) {
    throw new TnlError("sdk.runtime_invalid", { cause });
  }
  return parseProjectRuntime(value);
}

export function serializeRuntimePayload(
  { namespace, services, worktree, oauth, webhooks, aliases }: ProjectMetadata,
  dev: boolean,
): string {
  const serialized = JSON.stringify(
    parseProjectRuntime({ namespace, services, worktree, oauth, webhooks, aliases, dev }),
  );
  if (byteLength(serialized) > maximumRuntimeBytes) throw new TnlError("sdk.runtime_invalid");
  return serialized;
}
function byteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}
