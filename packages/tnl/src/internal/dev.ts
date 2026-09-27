import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as http from "node:http";
import { isIP } from "node:net";
import * as os from "node:os";
import * as path from "node:path";
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
const registrationTimeoutMilliseconds = 10 * 60 * 1000;
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
  readonly tunnelID: `tunnel_${string}`;
}

export type CanonicalLoopbackTarget = `http://${string}`;

export function readDevelopmentContext(
  environment: TnlDevEnvironment = process.env,
  cwd: string = process.cwd(),
): DevelopmentContext {
  const protocol = environment.TNL_DEV_PROTOCOL;
  if (protocol !== undefined) {
    if (protocol !== protocolVersion) {
      throw new Error(
        `unsupported tnl dev protocol ${JSON.stringify(protocol)}; upgrade tnl and its framework integrations`,
      );
    }
    return Object.freeze({
      bootstrap: parseBootstrapEnvironment(environment),
      localProject: null,
    });
  }
  if (environment.TNL_DEV_SOCKET !== undefined || environment.TNL_DEV_PORT !== undefined) {
    throw new Error(
      `TNL_DEV_PROTOCOL=${protocolVersion} is required with tnl dev bootstrap values`,
    );
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
    throw new Error("tnl framework name is invalid");
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
  return parseAssignment(response, bootstrap, framework);
}

export function canonicalLoopbackTarget(host: string, port: number): CanonicalLoopbackTarget {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("tnl listener port must be between 1 and 65535");
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
  throw new Error("tnl development target must listen on localhost or all interfaces");
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
        throw new Error(`${file} must be a regular file`);
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
        throw error;
      }
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
    throw new Error(`TNL_DEV_SOCKET is required by tnl dev protocol ${protocolVersion}`);
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
    throw error;
  }
  if (
    !directoryStat.isDirectory() ||
    directoryStat.uid !== getuid() ||
    (directoryStat.mode & 0o777) !== 0o700 ||
    !socketStat.isSocket() ||
    socketStat.uid !== getuid() ||
    (socketStat.mode & 0o777) !== 0o600
  ) {
    throw new Error("tnl dev runtime directory or socket has unsafe ownership or permissions");
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
    throw new Error("tnl dev returned an inconsistent tunnel assignment");
  }
  if (typeof object.tunnelID !== "string" || !/^tunnel_[a-f0-9]{32}$/.test(object.tunnelID)) {
    throw new Error("tnl dev returned an invalid tunnel ID");
  }
  if (object.service !== null && !validServiceName(object.service)) {
    throw new Error("tnl dev returned an invalid service");
  }
  const responseNamespace = requiredHostname(object.namespace, "tnl dev returned namespace");
  const hostname = requiredHostname(object.hostname, "tnl dev returned public hostname");
  const publicURL: `https://${string}` = `https://${hostname}`;
  if (object.publicURL !== publicURL) {
    throw new Error("tnl dev returned an invalid public URL");
  }
  const project = parseProjectRuntime(object.project, "tnl dev project metadata");
  if (!project.dev) {
    throw new Error("tnl dev returned project metadata outside tnl dev");
  }
  const projectNamespace =
    object.service === null ? project.namespace : project.services[object.service]?.namespace;
  if (projectNamespace !== responseNamespace) {
    throw new Error("tnl dev returned inconsistent project metadata");
  }
  if (object.service !== null && project.services[object.service] === undefined) {
    throw new Error("tnl dev returned inconsistent project metadata");
  }
  if (object.service !== null && project.services[object.service]?.hostname !== hostname) {
    throw new Error("tnl dev returned inconsistent project metadata");
  }

  return Object.freeze({
    ...bootstrap,
    framework,
    hostname,
    namespace: responseNamespace,
    project,
    publicURL,
    service: object.service,
    tunnelID: object.tunnelID as `tunnel_${string}`,
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
    throw new Error(`${description} is not valid JSON`, { cause: error });
  }
  return parseProjectDocumentValue(value, description, projectRoot);
}

function parseProjectDocumentValue(
  value: unknown,
  description: string,
  projectRoot: string,
): ProjectDocument {
  const object = record(value, description);
  exactKeys(object, ["dev", "namespace", "serviceDirectories", "services", "version"], description);
  if (object.version !== 1) {
    throw new Error(`${description} has an unsupported version`);
  }
  if (typeof object.dev !== "boolean") {
    throw new Error(`${description} has an invalid dev value`);
  }
  if (object.dev) {
    throw new Error(`${description} cannot be marked as running under tnl dev`);
  }
  const project = parseProjectMetadata(
    { namespace: object.namespace, services: object.services },
    description,
  );
  const directoryValues = record(object.serviceDirectories, `${description} service directories`);
  const names = Object.keys(project.services);
  if (
    Object.keys(directoryValues).length !== names.length ||
    names.some((name) => !Object.hasOwn(directoryValues, name))
  ) {
    throw new Error(`${description} requires one directory for every service`);
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
  return Object.freeze({ namespace: document.namespace, services: document.services });
}

function selectService(document: ProjectDocument, cwd: string): string | null {
  const absoluteCwd = absoluteNormalizedPath(cwd, "working directory");
  const canonicalCwd = fs.realpathSync.native(absoluteCwd);
  const canonicalRoot = fs.realpathSync.native(document.projectRoot);
  if (!pathWithin(canonicalCwd, canonicalRoot)) {
    throw new Error("working directory is outside the discovered tnl project");
  }
  const matches = Object.entries(document.serviceDirectories)
    .map(
      ([name, directory]) =>
        [name, canonicalPath(path.join(document.projectRoot, directory))] as const,
    )
    .filter(([, directory]) => pathWithin(canonicalCwd, directory))
    .sort((left, right) => right[1].length - left[1].length);
  if (matches.length > 1 && matches[0]?.[1].length === matches[1]?.[1].length) {
    throw new Error("working directory matches multiple tnl service directories");
  }
  return matches[0]?.[0] ?? null;
}

function relativeDirectory(value: unknown, description: string): string {
  if (typeof value !== "string" || value === "" || value.includes("\0") || path.isAbsolute(value)) {
    throw new Error(`${description} must be a non-empty relative path`);
  }
  const normalized = path.normalize(value);
  if (
    normalized === ".." ||
    normalized.startsWith(`..${path.sep}`) ||
    normalized.split(path.sep).join("/") !== value
  ) {
    throw new Error(`${description} must be a clean relative path`);
  }
  return value;
}

function sendRequest(
  bootstrap: TnlDevBootstrap,
  framework: string,
  requestPath: string,
  body: string,
  expectedStatus: number,
  operation: TnlDevOperation,
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
    const failTransport = (phase: "request" | "response", cause: unknown) => {
      fail(new Error(`tnl dev ${operation} ${phase} failed`, { cause }));
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
            fail(new Error("tnl dev returned an oversized response"));
            response.destroy();
            return;
          }
          const chunks: Buffer[] = [];
          let size = 0;
          response.on("data", (chunk: Buffer) => {
            if (settled) return;
            size += chunk.length;
            if (size > maximumResponseBytes) {
              fail(new Error("tnl dev returned an oversized response"));
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
                new Error(
                  `tnl dev rejected the ${framework} request with status ${response.statusCode}${data ? `: ${data}` : ""}`,
                ),
              );
              return;
            }
            if (expectedStatus === 204) {
              if (data !== "") {
                fail(new Error("tnl dev returned an unexpected target response"));
                return;
              }
              succeed(undefined);
              return;
            }
            if (response.headers["content-type"]?.split(";", 1)[0]?.trim() !== "application/json") {
              fail(new Error("tnl dev returned a non-JSON configuration"));
              return;
            }
            try {
              succeed(JSON.parse(data));
            } catch (error) {
              fail(new Error("tnl dev returned an invalid configuration", { cause: error }));
            }
          });
        },
      );
    } catch (error) {
      failTransport("request", error);
      return;
    }
    request.setTimeout(registrationTimeoutMilliseconds, () => {
      request.destroy(new Error("timed out configuring the target with tnl dev"));
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
      throw new Error(`${file} must be a regular file`);
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
      throw new Error(`${file} exceeds ${maximumDocumentBytes} bytes`);
    }
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, length));
    } catch (error) {
      throw new Error(`${file} is not valid UTF-8`, { cause: error });
    }
  } finally {
    fs.closeSync(descriptor);
  }
}

function absoluteNormalizedPath(value: unknown, description: string): string {
  if (
    typeof value !== "string" ||
    value === "" ||
    !path.isAbsolute(value) ||
    path.normalize(value) !== value
  ) {
    throw new Error(`${description} must be an absolute normalized path`);
  }
  return value;
}

/** Parses a decimal listener port from 1 through 65535. */
export function parseListenerPort(value: string, source: string): number {
  if (!/^[0-9]+$/.test(value)) {
    throw new Error(`${source} must be a port between 1 and 65535`);
  }
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${source} must be a port between 1 and 65535`);
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
