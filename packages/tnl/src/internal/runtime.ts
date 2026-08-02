const maximumRuntimeBytes = 64 * 1024;
const maximumServices = 32;
const serviceNamePattern = /^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$/;

export interface ProjectServiceMetadata {
  readonly memberNamespace: string;
  readonly hostname: string;
  readonly url: `https://${string}`;
}

export interface ProjectMetadata {
  readonly memberNamespace: string;
  readonly services: Readonly<Record<string, ProjectServiceMetadata>>;
}

export interface ProjectRuntime extends ProjectMetadata {
  readonly runningUnderTnlDev: boolean;
}

/** Checks browser-safe project metadata and makes it read-only. */
export function parseProjectMetadata(value: unknown, description: string): ProjectMetadata {
  const object = record(value, description);
  exactKeys(object, ["memberNamespace", "services"], description);
  const memberNamespace = requiredHostname(
    object.memberNamespace,
    `${description} member namespace`,
  );
  const servicesObject = record(object.services, `${description} services`);
  const entries = Object.entries(servicesObject);
  if (entries.length > maximumServices) {
    throw new Error(`${description} may contain at most ${maximumServices} services`);
  }

  const services: Record<string, ProjectServiceMetadata> = {};
  const hostnames = new Set<string>();
  for (const [name, value] of entries) {
    if (!validServiceName(name)) {
      throw new Error(`${description} contains an invalid service name ${JSON.stringify(name)}`);
    }
    const service = record(value, `${description} service ${JSON.stringify(name)}`);
    exactKeys(
      service,
      ["hostname", "memberNamespace", "url"],
      `${description} service ${JSON.stringify(name)}`,
    );
    const serviceMemberNamespace = requiredHostname(
      service.memberNamespace,
      `${description} service ${JSON.stringify(name)} member namespace`,
    );
    const hostname = requiredHostname(
      service.hostname,
      `${description} service ${JSON.stringify(name)} hostname`,
    );
    if (service.url !== `https://${hostname}`) {
      throw new Error(`${description} service ${JSON.stringify(name)} has an invalid URL`);
    }
    if (hostnames.has(hostname)) {
      throw new Error(`${description} contains duplicate service hostname ${hostname}`);
    }
    hostnames.add(hostname);
    services[name] = Object.freeze({
      memberNamespace: serviceMemberNamespace,
      hostname,
      url: service.url as `https://${string}`,
    });
  }

  return Object.freeze({
    memberNamespace,
    services: Object.freeze(services),
  });
}

/** Reports whether a value is a valid 1-32 character ASCII service name. */
export function validServiceName(value: unknown): value is string {
  return typeof value === "string" && serviceNamePattern.test(value);
}

export function parseRuntimePayload(serialized: string | undefined): ProjectRuntime | undefined {
  if (serialized === undefined) {
    return undefined;
  }
  if (byteLength(serialized) > maximumRuntimeBytes) {
    throw new Error(`tnl runtime payload exceeds ${maximumRuntimeBytes} bytes`);
  }

  let value: unknown;
  try {
    value = JSON.parse(serialized);
  } catch (error) {
    throw new Error("tnl runtime payload is not valid JSON", { cause: error });
  }
  return parseProjectRuntime(value, "tnl runtime payload");
}

export function parseProjectRuntime(value: unknown, description: string): ProjectRuntime {
  const object = record(value, description);
  exactKeys(object, ["memberNamespace", "runningUnderTnlDev", "services"], description);
  if (typeof object.runningUnderTnlDev !== "boolean") {
    throw new Error(`${description} has an invalid runningUnderTnlDev value`);
  }
  const project = parseProjectMetadata(
    { memberNamespace: object.memberNamespace, services: object.services },
    description,
  );
  return Object.freeze({
    ...project,
    runningUnderTnlDev: object.runningUnderTnlDev,
  });
}

export function serializeRuntimePayload(
  project: ProjectMetadata,
  runningUnderTnlDev: boolean,
): string {
  const serialized = JSON.stringify({
    memberNamespace: project.memberNamespace,
    runningUnderTnlDev,
    services: project.services,
  });
  if (byteLength(serialized) > maximumRuntimeBytes) {
    throw new Error(`tnl runtime payload exceeds ${maximumRuntimeBytes} bytes`);
  }
  return serialized;
}

export function requiredHostname(value: unknown, description: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 253) {
    throw new Error(`${description} is invalid`);
  }
  if (value !== value.toLowerCase() || value.endsWith(".")) {
    throw new Error(`${description} is invalid`);
  }
  const labels = value.split(".");
  if (
    labels.some(
      (label) =>
        label.length === 0 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    )
  ) {
    throw new Error(`${description} is invalid`);
  }
  if (
    labels.length === 4 &&
    labels.every((label) => /^[0-9]+$/.test(label) && Number(label) <= 255)
  ) {
    throw new Error(`${description} is invalid`);
  }
  return value;
}

export function exactKeys(
  object: Record<string, unknown>,
  expected: readonly string[],
  description: string,
): void {
  const keys = Object.keys(object).sort();
  const sortedExpected = [...expected].sort();
  if (
    keys.length !== sortedExpected.length ||
    keys.some((key, index) => key !== sortedExpected[index])
  ) {
    throw new Error(`${description} has an invalid shape`);
  }
}

export function record(value: unknown, description: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${description} must be an object`);
  }
  return value as Record<string, unknown>;
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}
