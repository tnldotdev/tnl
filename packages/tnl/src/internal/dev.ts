import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as http from "node:http";
import { isIP } from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { TnlError, classifyTnlError } from "../errors.js";
import {
  exactKeys,
  parseProjectMetadata,
  parseProjectRuntime,
  record,
  requiredHostname,
  serializeRuntimePayload,
  validServiceName,
  type ProjectMetadata,
  type ProjectRuntime,
} from "./runtime.js";

const protocolVersion = "1";
const maximumDocumentBytes = 64 * 1024;
const maximumResponseBytes = 64 * 1024;
export const registrationTimeoutMilliseconds: number = 10 * 60 * 1000;
type TnlDevOperation = "configuration" | "target registration";

export type TnlDevEnvironment = Readonly<Record<string, string | undefined>>;

export interface TnlDevBootstrap {
  readonly port?: number;
  readonly socket: string;
}

export interface ProjectDocument extends ProjectMetadata {
  readonly projectRoot: string;
  readonly dev: boolean;
  readonly serviceDirectories: Readonly<Record<string, string>>;
  readonly version: 1;
}

export interface ProjectDiscovery {
  readonly document: ProjectDocument;
  readonly file: string;
  readonly project: ProjectMetadata;
  readonly service: string | null;
}

export interface DevelopmentContext {
  readonly bootstrap: TnlDevBootstrap | null;
  readonly localProject: ProjectMetadata | null;
}

export interface TnlTunnelAssignment extends TnlDevBootstrap {
  readonly framework: string;
  readonly hostname: string;
  readonly namespace: string;
  readonly project: ProjectRuntime;
  readonly publicURL: `https://${string}`;
  readonly service: string | null;
  readonly tunnelID: `tun_${string}`;
}

export type CanonicalLoopbackTarget = `http://${string}`;

export function readDevelopmentContext(
  environment: TnlDevEnvironment = process.env,
  cwd: string = process.cwd(),
): DevelopmentContext {
  const protocol = environment.TNL_DEV_PROTOCOL;
  if (protocol !== undefined) {
    if (protocol !== protocolVersion) {
      throw new TnlError("sdk.protocol_unsupported");
    }
    return Object.freeze({
      bootstrap: parseBootstrapEnvironment(environment),
      localProject: null,
    });
  }
  if (environment.TNL_DEV_SOCKET !== undefined || environment.TNL_DEV_PORT !== undefined) {
    throw new TnlError("sdk.configuration_invalid");
  }

  const discovery = discoverProject(cwd);
  if (discovery === null) {
    return Object.freeze({ bootstrap: null, localProject: null });
  }
  const socket = discoverDevSocket(discovery, environment);
  return Object.freeze({
    bootstrap: socket === null ? null : Object.freeze({ socket }),
    localProject: discovery.project,
  });
}

export async function requestTunnelAssignment(
  framework: string,
  bootstrap: TnlDevBootstrap,
): Promise<TnlTunnelAssignment> {
  if (!/^[a-z]{1,32}$/.test(framework)) {
    throw new TnlError("sdk.configuration_invalid");
  }
  const body = JSON.stringify({ protocol: 1, framework });
  const response = await sendRequest(
    bootstrap,
    framework,
    "/v1/configure",
    body,
    200,
    "configuration",
  );
  try {
    return parseAssignment(response, bootstrap, framework);
  } catch (cause) {
    throw new TnlError("sdk.response_invalid", { cause });
  }
}

export function canonicalLoopbackTarget(host: string, port: number): CanonicalLoopbackTarget {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new TnlError("sdk.target_invalid");
  }
  const hostname = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  const lowerHostname = hostname.toLowerCase();
  if (lowerHostname === "localhost" || hostname === "0.0.0.0") {
    return `http://127.0.0.1:${port}`;
  }
  if (hostname === "::") {
    return `http://[::1]:${port}`;
  }
  if (isIP(hostname) === 4 && hostname.startsWith("127.")) {
    return `http://${hostname}:${port}`;
  }
  if (hostname === "::1") {
    return `http://[::1]:${port}`;
  }
  throw new TnlError("sdk.target_invalid");
}

export async function registerLocalTarget(
  assignment: TnlTunnelAssignment,
  target: CanonicalLoopbackTarget,
): Promise<void> {
  const body = JSON.stringify({ protocol: 1, framework: assignment.framework, target });
  await sendRequest(
    assignment,
    assignment.framework,
    "/v1/target",
    body,
    204,
    "target registration",
  );
}

export function runtimePayload(project: ProjectMetadata, dev: boolean): string {
  return serializeRuntimePayload(project, dev);
}

export function discoverProject(cwd: string): ProjectDiscovery | null {
  let directory = absoluteNormalizedPath(cwd, "working directory");
  for (;;) {
    const file = path.join(directory, ".tnl", "project.json");
    try {
      const stat = fs.lstatSync(file);
      if (!stat.isFile()) {
        throw new TnlError("sdk.runtime_invalid");
      }
      const document = parseProjectDocument(readBoundedFile(file), file, directory);
      const service = selectService(document, cwd);
      return Object.freeze({
        document,
        file,
        project: projectMetadata(document),
        service,
      });
    } catch (error) {
      if (!isMissing(error)) {
        throw classifyTnlError(error, "sdk.project_unavailable");
      }
    }

    // a nested repository or Git worktree must not inherit an unrelated
    // ancestor's browser-safe project metadata.
    try {
      fs.lstatSync(path.join(directory, ".git"));
      return null;
    } catch (error) {
      if (!isMissing(error)) throw classifyTnlError(error, "sdk.project_unavailable");
    }

    const parent = path.dirname(directory);
    if (parent === directory) {
      return null;
    }
    directory = parent;
  }
}

export function socketIdentity(projectRoot: string, service: string | null): string {
  return createHash("sha256")
    .update(`${projectRoot}\0${service ?? ""}`)
    .digest("hex")
    .slice(0, 16);
}

function parseBootstrapEnvironment(environment: TnlDevEnvironment): TnlDevBootstrap {
  const socket = environment.TNL_DEV_SOCKET;
  if (socket === undefined || socket === "") {
    throw new TnlError("sdk.configuration_invalid");
  }
  const rawPort = environment.TNL_DEV_PORT;
  if (rawPort === undefined) {
    return Object.freeze({ socket });
  }
  return Object.freeze({ port: parseListenerPort(rawPort, "TNL_DEV_PORT"), socket });
}

function discoverDevSocket(
  discovery: ProjectDiscovery,
  environment: TnlDevEnvironment,
): string | null {
  const getuid = process.getuid;
  if (getuid === undefined) {
    return null;
  }
  const base = environment.XDG_RUNTIME_DIR || os.tmpdir();
  const directory = path.join(base, `tnl-${getuid()}`);
  const socket = path.join(
    directory,
    `dev-${socketIdentity(discovery.document.projectRoot, discovery.service)}.sock`,
  );
  let directoryStat: fs.Stats;
  let socketStat: fs.Stats;
  try {
    directoryStat = fs.lstatSync(directory);
    socketStat = fs.lstatSync(socket);
  } catch (error) {
    if (isMissing(error)) {
      return null;
    }
    throw classifyTnlError(error, "sdk.dev_unavailable");
  }
  if (
    !directoryStat.isDirectory() ||
    directoryStat.uid !== getuid() ||
    (directoryStat.mode & 0o777) !== 0o700 ||
    !socketStat.isSocket() ||
    socketStat.uid !== getuid() ||
    (socketStat.mode & 0o777) !== 0o600
  ) {
    throw new TnlError("sdk.configuration_invalid");
  }
  return socket;
}

function parseAssignment(
  value: unknown,
  bootstrap: TnlDevBootstrap,
  framework: string,
): TnlTunnelAssignment {
  const object = record(value, "tnl dev response");
  exactKeys(
    object,
    ["hostname", "namespace", "project", "protocol", "publicURL", "service", "tunnelID"],
    "tnl dev response",
  );
  if (object.protocol !== 1) {
    throw new TnlError("sdk.response_invalid");
  }
  if (typeof object.tunnelID !== "string" || !/^tun_[A-Za-z0-9]{22}$/.test(object.tunnelID)) {
    throw new TnlError("sdk.response_invalid");
  }
  if (object.service !== null && !validServiceName(object.service)) {
    throw new TnlError("sdk.response_invalid");
  }
  const responseNamespace = requiredHostname(object.namespace, "tnl dev returned namespace");
  const hostname = requiredHostname(object.hostname, "tnl dev returned public hostname");
  const publicURL: `https://${string}` = `https://${hostname}`;
  if (object.publicURL !== publicURL) {
    throw new TnlError("sdk.response_invalid");
  }
  const project = parseProjectRuntime(object.project, "tnl dev project metadata");
  if (!project.dev) {
    throw new TnlError("sdk.response_invalid");
  }
  const projectNamespace =
    object.service === null ? project.namespace : project.services[object.service]?.namespace;
  if (projectNamespace !== responseNamespace) {
    throw new TnlError("sdk.response_invalid");
  }
  if (object.service !== null && project.services[object.service] === undefined) {
    throw new TnlError("sdk.response_invalid");
  }
  if (object.service !== null && project.services[object.service]?.hostname !== hostname) {
    throw new TnlError("sdk.response_invalid");
  }

  return Object.freeze({
    ...bootstrap,
    framework,
    hostname,
    namespace: responseNamespace,
    project,
    publicURL,
    service: object.service,
    tunnelID: object.tunnelID as `tun_${string}`,
  });
}

function parseProjectDocument(
  serialized: string,
  description: string,
  projectRoot: string,
): ProjectDocument {
  let value: unknown;
  try {
    value = JSON.parse(serialized);
  } catch (error) {
    throw new TnlError("sdk.runtime_invalid", { cause: error });
  }
  return parseProjectDocumentValue(value, description, projectRoot);
}

function parseProjectDocumentValue(
  value: unknown,
  description: string,
  projectRoot: string,
): ProjectDocument {
  const object = record(value, description);
  exactKeys(
    object,
    [
      "dev",
      "namespace",
      "serviceDirectories",
      "services",
      "version",
      ...["oauth", "webhooks"].filter((key) => Object.hasOwn(object, key)),
    ],
    description,
  );
  if (object.version !== 1) {
    throw new TnlError("sdk.runtime_invalid");
  }
  if (typeof object.dev !== "boolean") {
    throw new TnlError("sdk.runtime_invalid");
  }
  if (object.dev) {
    throw new TnlError("sdk.runtime_invalid");
  }
  const project = parseProjectMetadata(
    {
      namespace: object.namespace,
      services: object.services,
      ...(Object.hasOwn(object, "oauth") ? { oauth: object.oauth } : {}),
      ...(Object.hasOwn(object, "webhooks") ? { webhooks: object.webhooks } : {}),
    },
    description,
  );
  const directoryValues = record(object.serviceDirectories, `${description} service directories`);
  const names = Object.keys(project.services);
  if (
    Object.keys(directoryValues).length !== names.length ||
    names.some((name) => !Object.hasOwn(directoryValues, name))
  ) {
    throw new TnlError("sdk.runtime_invalid");
  }
  const serviceDirectories: Record<string, string> = {};
  for (const name of names) {
    serviceDirectories[name] = relativeDirectory(
      directoryValues[name],
      `${description} service ${JSON.stringify(name)} directory`,
    );
  }
  return Object.freeze({
    ...project,
    projectRoot,
    dev: object.dev,
    serviceDirectories: Object.freeze(serviceDirectories),
    version: 1,
  });
}

function projectMetadata(document: ProjectDocument): ProjectMetadata {
  return Object.freeze({
    namespace: document.namespace,
    services: document.services,
    ...(document.oauth === undefined ? {} : { oauth: document.oauth }),
    ...(document.webhooks === undefined ? {} : { webhooks: document.webhooks }),
  });
}

function selectService(document: ProjectDocument, cwd: string): string | null {
  const absoluteCwd = absoluteNormalizedPath(cwd, "working directory");
  const canonicalCwd = fs.realpathSync.native(absoluteCwd);
  const canonicalRoot = fs.realpathSync.native(document.projectRoot);
  if (!pathWithin(canonicalCwd, canonicalRoot)) {
    throw new TnlError("sdk.runtime_invalid");
  }
  const matches = Object.entries(document.serviceDirectories)
    .map(
      ([name, directory]) =>
        [name, canonicalPath(path.join(document.projectRoot, directory))] as const,
    )
    .filter(([, directory]) => pathWithin(canonicalCwd, directory))
    .sort((left, right) => right[1].length - left[1].length);
  if (matches.length > 1 && matches[0]?.[1].length === matches[1]?.[1].length) {
    throw new TnlError("sdk.runtime_invalid");
  }
  return matches[0]?.[0] ?? null;
}

function relativeDirectory(value: unknown, _description: string): string {
  if (typeof value !== "string" || value === "" || value.includes("\0") || path.isAbsolute(value)) {
    throw new TnlError("sdk.runtime_invalid");
  }
  const normalized = path.normalize(value);
  if (
    normalized === ".." ||
    normalized.startsWith(`..${path.sep}`) ||
    normalized.split(path.sep).join("/") !== value
  ) {
    throw new TnlError("sdk.runtime_invalid");
  }
  return value;
}

function sendRequest(
  bootstrap: TnlDevBootstrap,
  _framework: string,
  requestPath: string,
  body: string,
  expectedStatus: number,
  _operation: TnlDevOperation,
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const succeed = (value: unknown) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const fail = (error: unknown) => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    const failTransport = (_phase: "request" | "response", cause: unknown) => {
      fail(new TnlError("sdk.dev_unavailable", { cause }));
    };

    let request: http.ClientRequest;
    try {
      request = http.request(
        {
          socketPath: bootstrap.socket,
          path: requestPath,
          method: "POST",
          headers: {
            "Content-Length": Buffer.byteLength(body),
            "Content-Type": "application/json",
          },
        },
        (response) => {
          response.on("error", (error) => failTransport("response", error));
          response.on("close", () => {
            if (!response.complete) {
              failTransport(
                "response",
                new Error("tnl dev response closed before it was complete"),
              );
            }
          });
          const declaredLength = Number(response.headers["content-length"]);
          if (Number.isFinite(declaredLength) && declaredLength > maximumResponseBytes) {
            fail(new TnlError("sdk.response_invalid"));
            response.destroy();
            return;
          }
          const chunks: Buffer[] = [];
          let size = 0;
          response.on("data", (chunk: Buffer) => {
            if (settled) return;
            size += chunk.length;
            if (size > maximumResponseBytes) {
              fail(new TnlError("sdk.response_invalid"));
              response.destroy();
              return;
            }
            chunks.push(chunk);
          });
          response.on("end", () => {
            if (!response.complete) {
              failTransport("response", new Error("tnl dev response ended before it was complete"));
              return;
            }
            const data = Buffer.concat(chunks).toString("utf8").trim();
            if (response.statusCode !== expectedStatus) {
              fail(
                new TnlError(
                  response.statusCode !== undefined && response.statusCode >= 500
                    ? "sdk.dev_unavailable"
                    : "sdk.request_rejected",
                ),
              );
              return;
            }
            if (expectedStatus === 204) {
              if (data !== "") {
                fail(new TnlError("sdk.response_invalid"));
                return;
              }
              succeed(undefined);
              return;
            }
            if (response.headers["content-type"]?.split(";", 1)[0]?.trim() !== "application/json") {
              fail(new TnlError("sdk.response_invalid"));
              return;
            }
            try {
              succeed(JSON.parse(data));
            } catch (error) {
              fail(new TnlError("sdk.response_invalid", { cause: error }));
            }
          });
        },
      );
    } catch (error) {
      failTransport("request", error);
      return;
    }
    request.setTimeout(registrationTimeoutMilliseconds, () => {
      request.destroy(new TnlError("sdk.dev_unavailable"));
    });
    request.on("error", (error) => failTransport("request", error));
    try {
      request.end(body);
    } catch (error) {
      failTransport("request", error);
    }
  });
}

function readBoundedFile(file: string): string {
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
  const descriptor = fs.openSync(file, flags);
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile()) {
      throw new TnlError("sdk.runtime_invalid");
    }
    const buffer = Buffer.allocUnsafe(maximumDocumentBytes + 1);
    let length = 0;
    for (;;) {
      const read = fs.readSync(descriptor, buffer, length, buffer.length - length, null);
      length += read;
      if (read === 0 || length === buffer.length) {
        break;
      }
    }
    if (length > maximumDocumentBytes) {
      throw new TnlError("sdk.runtime_invalid");
    }
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, length));
    } catch (error) {
      throw new TnlError("sdk.runtime_invalid", { cause: error });
    }
  } finally {
    fs.closeSync(descriptor);
  }
}

function absoluteNormalizedPath(value: unknown, _description: string): string {
  if (
    typeof value !== "string" ||
    value === "" ||
    !path.isAbsolute(value) ||
    path.normalize(value) !== value
  ) {
    throw new TnlError("sdk.configuration_invalid");
  }
  return value;
}

/** Parses a decimal listener port from 1 through 65535. */
export function parseListenerPort(value: string, _source: string): number {
  if (!/^[0-9]+$/.test(value)) {
    throw new TnlError("sdk.target_invalid");
  }
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new TnlError("sdk.target_invalid");
  }
  return port;
}

function pathWithin(value: string, root: string): boolean {
  const relative = path.relative(root, value);
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`));
}

function canonicalPath(value: string): string {
  try {
    return fs.realpathSync.native(value);
  } catch {
    return value;
  }
}

function isMissing(error: unknown): boolean {
  return error !== null && typeof error === "object" && "code" in error && error.code === "ENOENT";
}
