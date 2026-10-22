import { TnlError } from "../errors.js";
import type { TnlWorktreeLabel } from "../config.gen.js";
import type { TnlProtocolRegistry } from "../project.js";
const maximumRuntimeBytes = 64 * 1024;
const maximumServices = 32;
const serviceNamePattern = /^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$/;

interface ServiceAddress {
  readonly namespace: string;
  readonly hostname: string;
  readonly port: number;
  readonly public: boolean;
}

export type ServiceProtocol = keyof TnlProtocolRegistry;

export interface HTTPServiceMetadata extends ServiceAddress {
  readonly protocol: "http";
  readonly url: `https://${string}`;
  readonly paths?: Readonly<Record<string, ProjectPathMetadata | undefined>>;
  readonly address?: never;
}

export type ProjectServiceMetadata =
  | HTTPServiceMetadata
  | (ServiceAddress &
      (
        | {
            readonly protocol: "postgres" | "mysql" | "tcp";
            readonly url?: never;
            readonly paths?: never;
          }
        | {
            readonly protocol: "kubernetes";
            readonly url: `https://${string}`;
            readonly paths?: never;
          }
      ));

export interface ProjectPathMetadata {
  readonly service: string;
  readonly url: `https://${string}`;
  readonly stripPrefix: boolean;
}

export interface ProjectMetadata {
  readonly worktree?: { readonly label: WorktreeLabel };
  readonly namespace: string;
  readonly services: Readonly<Record<string, ProjectServiceMetadata | undefined>>;
  readonly oauth?: IntegrationOrigin;
  readonly webhooks?: Readonly<Record<string, WebhookMetadata | undefined>>;
  readonly aliases?: Readonly<Record<string, AliasMetadata | undefined>>;
}

export type WorktreeLabel = TnlWorktreeLabel;

export interface AliasMetadata extends IntegrationOrigin {
  readonly service: string;
}

export interface WebhookMetadata extends IntegrationOrigin {
  readonly service: string;
  readonly path: string;
  readonly methods: readonly WebhookMethod[];
}

export type WebhookMethod = "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface IntegrationOrigin {
  readonly hostname: string;
  readonly url: `https://${string}`;
}

export interface ProjectRuntime extends ProjectMetadata {
  readonly dev: boolean;
}

/** returns the public hostnames that can reach this service. */
export function serviceHostnames(assignment: {
  readonly hostname: string | undefined;
  readonly service: string;
  readonly project: ProjectRuntime;
}): string[] {
  const hostnames = new Set(assignment.hostname === undefined ? [] : [assignment.hostname]);
  for (const alias of Object.values(assignment.project.aliases ?? {})) {
    if (
      alias !== undefined &&
      (alias.service === assignment.service ||
        Object.values(assignment.project.services[alias.service]?.paths ?? {}).some(
          (mount) => mount?.service === assignment.service,
        ))
    ) {
      hostnames.add(alias.hostname);
    }
  }
  return [...hostnames];
}

/** Checks browser-safe project metadata and makes it read-only. */
export function parseProjectMetadata(value: unknown, description: string): ProjectMetadata {
  const object = record(value, description);
  exactKeys(object, ["namespace", "services", ...optionalProjectKeys(object)], description);
  const worktree = object.worktree === undefined ? undefined : parseWorktree(object.worktree);
  const servicesObject = record(object.services, `${description} services`);
  const entries = Object.entries(servicesObject);
  const projectNamespace =
    object.namespace === "" &&
    entries.length === 0 &&
    object.oauth === undefined &&
    object.webhooks === undefined &&
    object.aliases === undefined
      ? ""
      : requiredHostname(object.namespace, `${description} namespace`);
  if (entries.length > maximumServices) {
    throw new TnlError("sdk.runtime_invalid");
  }

  const services: Record<string, ProjectServiceMetadata> = Object.create(null);
  const hostnames = new Set<string>();
  for (const [name, value] of entries) {
    if (!validServiceName(name)) {
      throw new TnlError("sdk.runtime_invalid");
    }
    const service = record(value, `${description} service ${JSON.stringify(name)}`);
    exactKeys(
      service,
      [
        "protocol",
        "hostname",
        "namespace",
        "port",
        "public",
        ...(["http", "kubernetes"].includes(String(service.protocol)) ? ["url"] : []),
        ...["paths"].filter((key) => Object.hasOwn(service, key)),
      ],
      `${description} service ${JSON.stringify(name)}`,
    );
    if (
      !["http", "postgres", "mysql", "tcp", "kubernetes"].includes(String(service.protocol)) ||
      !Number.isInteger(service.port) ||
      typeof service.port !== "number" ||
      service.port < 1 ||
      service.port > 65535 ||
      typeof service.public !== "boolean"
    ) {
      throw new TnlError("sdk.runtime_invalid");
    }
    const serviceNamespace = requiredHostname(
      service.namespace,
      `${description} service ${JSON.stringify(name)} namespace`,
    );
    const hostname = requiredHostname(
      service.hostname,
      `${description} service ${JSON.stringify(name)} hostname`,
    );
    if (hostnames.has(hostname)) {
      throw new TnlError("sdk.runtime_invalid");
    }
    hostnames.add(hostname);
    if (
      service.protocol === "postgres" ||
      service.protocol === "mysql" ||
      service.protocol === "tcp"
    ) {
      if (service.paths !== undefined) throw new TnlError("sdk.runtime_invalid");
      services[name] = Object.freeze({
        protocol: service.protocol,
        namespace: serviceNamespace,
        hostname,
        port: service.port,
        public: service.public,
      });
      continue;
    }
    if (typeof service.url !== "string") throw new TnlError("sdk.runtime_invalid");
    let endpoint: URL;
    try {
      endpoint = new URL(service.url);
    } catch {
      throw new TnlError("sdk.runtime_invalid");
    }
    const port = endpoint.port === "" ? 443 : Number(endpoint.port);
    const url: `https://${string}` = `https://${hostname}${port === 443 ? "" : `:${port}`}`;
    if (!Number.isInteger(port) || port !== service.port || service.url !== url)
      throw new TnlError("sdk.runtime_invalid");
    let paths: Readonly<Record<string, ProjectPathMetadata | undefined>> | undefined;
    if (service.paths !== undefined) {
      if (service.protocol !== "http") throw new TnlError("sdk.runtime_invalid");
      const pathsObject = record(
        service.paths,
        `${description} service ${JSON.stringify(name)} paths`,
      );
      if (Object.keys(pathsObject).length > 32) {
        throw new TnlError("sdk.runtime_invalid");
      }
      const parsedPaths: Record<string, ProjectPathMetadata> = Object.create(null);
      for (const [prefix, value] of Object.entries(pathsObject)) {
        if (!validMountPrefix(prefix)) {
          throw new TnlError("sdk.runtime_invalid");
        }
        const mount = record(value, `${description} path mount ${JSON.stringify(prefix)}`);
        exactKeys(
          mount,
          ["service", "url", "stripPrefix"],
          `${description} path mount ${JSON.stringify(prefix)}`,
        );
        if (
          !validServiceName(mount.service) ||
          mount.service === name ||
          mount.url !== `${url}${prefix}` ||
          typeof mount.stripPrefix !== "boolean"
        ) {
          throw new TnlError("sdk.runtime_invalid");
        }
        parsedPaths[prefix] = Object.freeze({
          service: mount.service,
          url: mount.url as `https://${string}`,
          stripPrefix: mount.stripPrefix,
        });
      }
      paths = Object.freeze(parsedPaths);
    }
    if (service.protocol === "kubernetes") {
      services[name] = Object.freeze({
        protocol: "kubernetes",
        namespace: serviceNamespace,
        hostname,
        port: service.port,
        public: service.public,
        url,
      });
      continue;
    }
    services[name] = Object.freeze({
      protocol: "http",
      namespace: serviceNamespace,
      hostname,
      port: service.port,
      public: service.public,
      url,
      ...(paths === undefined ? {} : { paths }),
    });
  }
  let oauth: IntegrationOrigin | undefined;
  if (object.oauth !== undefined) {
    oauth = parseIntegrationOrigin(object.oauth, `${description} oauth`);
  }

  let webhooks: Readonly<Record<string, WebhookMetadata | undefined>> | undefined;
  if (object.webhooks !== undefined) {
    const values = record(object.webhooks, `${description} webhooks`);
    if (Object.keys(values).length > 32) throw new TnlError("sdk.runtime_invalid");
    const parsed: Record<string, WebhookMetadata> = Object.create(null);
    for (const [name, raw] of Object.entries(values)) {
      const endpoint = record(raw, `${description} webhook ${name}`);
      exactKeys(
        endpoint,
        ["hostname", "url", "service", "path", "methods"],
        `${description} webhook ${name}`,
      );
      const hostname = requiredHostname(
        endpoint.hostname,
        `${description} webhook ${name} hostname`,
      );
      if (
        !validServiceName(name) ||
        typeof endpoint.path !== "string" ||
        !validMountPrefix(endpoint.path) ||
        endpoint.url !== `https://${hostname}${endpoint.path}` ||
        !(
          (endpoint.service === "" && entries.length === 0) ||
          (validServiceName(endpoint.service) && services[endpoint.service]?.protocol === "http")
        ) ||
        !Array.isArray(endpoint.methods) ||
        endpoint.methods.length === 0 ||
        endpoint.methods.length > 7 ||
        endpoint.methods.some((value: unknown) => !isWebhookMethod(value)) ||
        new Set(endpoint.methods).size !== endpoint.methods.length
      ) {
        throw new TnlError("sdk.runtime_invalid");
      }
      parsed[name] = Object.freeze({
        hostname,
        url: endpoint.url as `https://${string}`,
        path: endpoint.path,
        service: endpoint.service,
        methods: Object.freeze(endpoint.methods as WebhookMethod[]),
      });
    }
    webhooks = Object.freeze(parsed);
  }

  let aliases: Readonly<Record<string, AliasMetadata | undefined>> | undefined;
  if (object.aliases !== undefined) {
    const values = record(object.aliases, `${description} aliases`);
    if (Object.keys(values).length > 32) throw new TnlError("sdk.runtime_invalid");
    const parsed: Record<string, AliasMetadata> = Object.create(null);
    for (const [name, raw] of Object.entries(values)) {
      const alias = record(raw, `${description} alias ${name}`);
      exactKeys(alias, ["hostname", "url", "service"], `${description} alias ${name}`);
      const origin = parseIntegrationOrigin(
        { hostname: alias.hostname, url: alias.url },
        `${description} alias ${name}`,
      );
      if (
        !validServiceName(name) ||
        !validServiceName(alias.service) ||
        services[alias.service]?.protocol !== "http" ||
        hostnames.has(origin.hostname)
      ) {
        throw new TnlError("sdk.runtime_invalid");
      }
      hostnames.add(origin.hostname);
      parsed[name] = Object.freeze({ ...origin, service: alias.service });
    }
    aliases = Object.freeze(parsed);
  }

  return Object.freeze({
    namespace: projectNamespace,
    ...(worktree === undefined ? {} : { worktree }),
    services: Object.freeze(services),
    ...(oauth === undefined ? {} : { oauth }),
    ...(webhooks === undefined ? {} : { webhooks }),
    ...(aliases === undefined ? {} : { aliases }),
  });
}

function isWebhookMethod(value: unknown): value is WebhookMethod {
  return (
    value === "GET" ||
    value === "HEAD" ||
    value === "OPTIONS" ||
    value === "POST" ||
    value === "PUT" ||
    value === "PATCH" ||
    value === "DELETE"
  );
}

function optionalProjectKeys(value: Record<string, unknown>): string[] {
  return ["oauth", "webhooks", "worktree", "aliases"].filter((key) => Object.hasOwn(value, key));
}

function parseWorktree(raw: unknown): { readonly label: WorktreeLabel } {
  const worktree = record(raw, "worktree");
  exactKeys(worktree, ["label"], "worktree");
  const label = record(worktree.label, "worktree label");
  const hasCheckout = Object.hasOwn(label, "checkout");
  exactKeys(
    label,
    ["project", "id", "fullLabel", ...(hasCheckout ? ["checkout"] : [])],
    "worktree label",
  );
  const project = requiredHostname(label.project, "worktree project label");
  const id = requiredHostname(label.id, "worktree label id");
  const fullLabel = requiredHostname(label.fullLabel, "worktree full label");
  const checkout = hasCheckout ? requiredHostname(label.checkout, "checkout label") : undefined;
  const parts = [project, ...(checkout === undefined ? [] : [checkout]), id];
  if (
    parts.some((part) => part.includes(".")) ||
    fullLabel.includes(".") ||
    fullLabel !== parts.join("-")
  ) {
    throw new TnlError("sdk.runtime_invalid");
  }
  return Object.freeze({
    label: Object.freeze({
      project,
      id,
      fullLabel,
      ...(checkout === undefined ? {} : { checkout }),
    }),
  });
}

function parseIntegrationOrigin(raw: unknown, description: string): IntegrationOrigin {
  const value = record(raw, description);
  exactKeys(value, ["hostname", "url"], description);
  const hostname = requiredHostname(value.hostname, `${description} hostname`);
  if (value.url !== `https://${hostname}`) throw new TnlError("sdk.runtime_invalid");
  return Object.freeze({ hostname, url: `https://${hostname}` });
}

/** Reports whether a value is a valid 1-32 character ASCII service name. */
export function validServiceName(value: unknown): value is string {
  return typeof value === "string" && serviceNamePattern.test(value);
}

function validMountPrefix(prefix: string): boolean {
  return (
    prefix.length >= 2 &&
    prefix.length <= 256 &&
    prefix.startsWith("/") &&
    !prefix.endsWith("/") &&
    prefix !== "/__tnl" &&
    !prefix.startsWith("/__tnl/") &&
    prefix
      .slice(1)
      .split("/")
      .every((segment) => segment !== "." && segment !== ".." && /^[A-Za-z0-9._~-]+$/.test(segment))
  );
}

export function parseRuntimePayload(serialized: string | undefined): ProjectRuntime | undefined {
  if (serialized === undefined) {
    return undefined;
  }
  if (byteLength(serialized) > maximumRuntimeBytes) {
    throw new TnlError("sdk.runtime_invalid");
  }

  let value: unknown;
  try {
    value = JSON.parse(serialized);
  } catch (error) {
    throw new TnlError("sdk.runtime_invalid", { cause: error });
  }
  return parseProjectRuntime(value, "tnl runtime payload");
}

export function parseProjectRuntime(value: unknown, description: string): ProjectRuntime {
  const object = record(value, description);
  exactKeys(object, ["dev", "namespace", "services", ...optionalProjectKeys(object)], description);
  if (typeof object.dev !== "boolean") {
    throw new TnlError("sdk.runtime_invalid");
  }
  const project = parseProjectMetadata(
    {
      namespace: object.namespace,
      services: object.services,
      ...(Object.hasOwn(object, "worktree") ? { worktree: object.worktree } : {}),
      ...(Object.hasOwn(object, "oauth") ? { oauth: object.oauth } : {}),
      ...(Object.hasOwn(object, "webhooks") ? { webhooks: object.webhooks } : {}),
      ...(Object.hasOwn(object, "aliases") ? { aliases: object.aliases } : {}),
    },
    description,
  );
  return Object.freeze({
    ...project,
    dev: object.dev,
  });
}

export function serializeRuntimePayload(project: ProjectMetadata, dev: boolean): string {
  const serialized = JSON.stringify(
    parseProjectRuntime(
      {
        namespace: project.namespace,
        dev,
        services: project.services,
        ...(project.worktree === undefined ? {} : { worktree: project.worktree }),
        ...(project.oauth === undefined ? {} : { oauth: project.oauth }),
        ...(project.webhooks === undefined ? {} : { webhooks: project.webhooks }),
        ...(project.aliases === undefined ? {} : { aliases: project.aliases }),
      },
      "tnl runtime payload",
    ),
  );
  if (byteLength(serialized) > maximumRuntimeBytes) {
    throw new TnlError("sdk.runtime_invalid");
  }
  return serialized;
}

export function requiredHostname(value: unknown, _description: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 253) {
    throw new TnlError("sdk.runtime_invalid");
  }
  if (value !== value.toLowerCase() || value.endsWith(".")) {
    throw new TnlError("sdk.runtime_invalid");
  }
  const labels = value.split(".");
  if (
    labels.some(
      (label) =>
        label.length === 0 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    )
  ) {
    throw new TnlError("sdk.runtime_invalid");
  }
  for (const label of labels) {
    if (label.startsWith("xn--") && !validALabel(label)) {
      throw new TnlError("sdk.runtime_invalid");
    }
  }
  if (
    labels.length === 4 &&
    labels.every((label) => /^[0-9]+$/.test(label) && Number(label) <= 255)
  ) {
    throw new TnlError("sdk.runtime_invalid");
  }
  return value;
}

function validALabel(label: string): boolean {
  try {
    return new URL(`https://${label}.example`).hostname === `${label}.example`;
  } catch {
    return false;
  }
}

export function exactKeys(
  object: Record<string, unknown>,
  expected: readonly string[],
  _description: string,
): void {
  const keys = Object.keys(object).sort();
  const sortedExpected = [...expected].sort();
  if (
    keys.length !== sortedExpected.length ||
    keys.some((key, index) => key !== sortedExpected[index])
  ) {
    throw new TnlError("sdk.runtime_invalid");
  }
}

export function record(value: unknown, _description: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TnlError("sdk.runtime_invalid");
  }
  return value as Record<string, unknown>;
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}
