import { TnlError } from "../errors.js";
const maximumRuntimeBytes = 64 * 1024;
const maximumServices = 32;
const serviceNamePattern = /^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$/;

export interface ProjectServiceMetadata {
  readonly namespace: string;
  readonly hostname: string;
  readonly url: `https://${string}`;
  readonly paths?: Readonly<Record<string, ProjectPathMetadata | undefined>>;
}

export interface ProjectPathMetadata {
  readonly service: string;
  readonly url: `https://${string}`;
  readonly stripPrefix: boolean;
}

export interface ProjectMetadata {
  readonly namespace: string;
  readonly services: Readonly<Record<string, ProjectServiceMetadata | undefined>>;
}

export interface ProjectRuntime extends ProjectMetadata {
  readonly dev: boolean;
}

/** Checks browser-safe project metadata and makes it read-only. */
export function parseProjectMetadata(value: unknown, description: string): ProjectMetadata {
  const object = record(value, description);
  exactKeys(object, ["namespace", "services"], description);
  const projectNamespace = requiredHostname(object.namespace, `${description} namespace`);
  const servicesObject = record(object.services, `${description} services`);
  const entries = Object.entries(servicesObject);
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
      Object.hasOwn(service, "paths")
        ? ["hostname", "namespace", "url", "paths"]
        : ["hostname", "namespace", "url"],
      `${description} service ${JSON.stringify(name)}`,
    );
    const serviceNamespace = requiredHostname(
      service.namespace,
      `${description} service ${JSON.stringify(name)} namespace`,
    );
    const hostname = requiredHostname(
      service.hostname,
      `${description} service ${JSON.stringify(name)} hostname`,
    );
    const url: `https://${string}` = `https://${hostname}`;
    if (service.url !== url) {
      throw new TnlError("sdk.runtime_invalid");
    }
    if (hostnames.has(hostname)) {
      throw new TnlError("sdk.runtime_invalid");
    }
    hostnames.add(hostname);
    let paths: Readonly<Record<string, ProjectPathMetadata | undefined>> | undefined;
    if (service.paths !== undefined) {
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
    services[name] = Object.freeze({
      namespace: serviceNamespace,
      hostname,
      url,
      ...(paths === undefined ? {} : { paths }),
    });
  }
  for (const service of Object.values(services)) {
    for (const mount of Object.values(service.paths ?? {})) {
      if (mount !== undefined && !Object.hasOwn(services, mount.service)) {
        throw new TnlError("sdk.runtime_invalid");
      }
    }
  }

  return Object.freeze({
    namespace: projectNamespace,
    services: Object.freeze(services),
  });
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
  exactKeys(object, ["dev", "namespace", "services"], description);
  if (typeof object.dev !== "boolean") {
    throw new TnlError("sdk.runtime_invalid");
  }
  const project = parseProjectMetadata(
    { namespace: object.namespace, services: object.services },
    description,
  );
  return Object.freeze({
    ...project,
    dev: object.dev,
  });
}

export function serializeRuntimePayload(project: ProjectMetadata, dev: boolean): string {
  const serialized = JSON.stringify({
    namespace: project.namespace,
    dev,
    services: project.services,
  });
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
