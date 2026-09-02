import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import * as http from "node:http";
import path from "node:path";
import { promisify } from "node:util";

const protocolVersion = "1";
const maximumResponseBytes = 4096;
const registrationTimeoutMilliseconds = 10 * 60 * 1000;
const execFileAsync = promisify(execFile);

declare const tnlHostnameBrand: unique symbol;
declare const tnlPublicURLBrand: unique symbol;
declare const tnlTunnelIDBrand: unique symbol;

/** A lowercase DNS hostname validated by tnl. */
export type TnlHostname = string & { readonly [tnlHostnameBrand]: true };

/** A public HTTPS origin validated by tnl. */
export type TnlPublicURL = `https://${string}` & { readonly [tnlPublicURLBrand]: true };

/** A tunnel identifier validated by tnl. */
export type TnlTunnelID = `tunnel_${string}` & { readonly [tnlTunnelIDBrand]: true };

/** Environment variables visible to the framework. */
export type TnlDevEnvironment = Readonly<Record<string, string | undefined>>;

/** Private connection details set by `tnl dev`. */
export interface TnlDevBootstrap {
  /** The port passed to `tnl dev --port`. Undefined means the framework may choose a port. */
  readonly port?: number;
  /** The local socket used to communicate with `tnl dev`. */
  readonly socket: string;
  /** The private token used to authenticate local requests. */
  readonly token: string;
}

/** Public tunnel details assigned by `tnl dev`. */
export interface TnlTunnelAssignment extends TnlDevBootstrap {
  /** The framework using the tunnel. */
  readonly framework: string;
  /** The public hostname the framework should allow. */
  readonly hostname: TnlHostname;
  /** The public HTTPS URL. */
  readonly publicURL: TnlPublicURL;
  /** The tunnel ID shown by `tnl status`. */
  readonly tunnelID: TnlTunnelID;
}

/** Public tunnel values formatted for a framework's client environment. */
export type TnlPublicEnvironment<Prefix extends string> = Readonly<
  { [Key in `${Prefix}TNL_HOSTNAME`]: TnlHostname } & {
    [Key in `${Prefix}TNL_TUNNEL_ID`]: TnlTunnelID;
  } & { [Key in `${Prefix}TNL_URL`]: TnlPublicURL }
>;

/** Options for the public development tunnel. */
export interface TnlOptions {
  /** Server to use. `--server` or `TNL_SERVER` overrides this value. */
  readonly server?: string;
  /**
   * Public name to use. This may be a managed name or a hostname under a name
   * you own. Command-line host selection overrides this value.
   */
  readonly name?: string;
  /** IP addresses or CIDR ranges allowed to access the tunnel. */
  readonly allowIP?: readonly string[];
  /**
   * Allow your current public IP address. This is added to `allowIP`. When used
   * alone, only your current public IP may access the tunnel.
   */
  readonly allowCurrentIP?: boolean;
}

/** Details about the current Git worktree or project directory. */
export interface TnlWorktree {
  /** True when `root` was found through Git. */
  readonly isGit: boolean;
  /** A DNS-safe version of `name` with a short stable suffix to avoid collisions. */
  readonly label: string;
  /** The directory name of `root`. */
  readonly name: string;
  /** The absolute worktree root, or the working directory when Git is unavailable. */
  readonly root: string;
}

/** Values available when computing tunnel options. */
export interface TnlOptionsContext {
  /** The framework's absolute working directory. */
  readonly cwd: string;
  /** A read-only copy of the framework's environment variables. */
  readonly env: TnlDevEnvironment;
  /** Information about the current worktree or project directory. */
  readonly worktree: TnlWorktree;
}

/**
 * Tunnel options or a function that computes them at startup. The function
 * runs only when the framework is started by `tnl dev`.
 */
export type TnlOptionsInput =
  | TnlOptions
  | ((context: TnlOptionsContext) => TnlOptions | Promise<TnlOptions>);

/** Tunnel configuration supplied by a framework integration. */
export interface TnlTunnelConfiguration {
  /** Lowercase framework name, such as `vite` or `next`. */
  readonly framework: string;
  /** Options supplied by the project. */
  readonly options?: TnlOptionsInput;
}

/** Reads the private environment variables set by `tnl dev`. */
export function readDevEnvironment(
  environment: TnlDevEnvironment = process.env,
): TnlDevBootstrap | null {
  const protocol = environment.TNL_DEV_PROTOCOL;
  if (protocol === undefined) {
    return null;
  }
  if (protocol !== protocolVersion) {
    throw new Error(
      `unsupported tnl dev protocol ${JSON.stringify(protocol)}; upgrade tnl and its framework integrations`,
    );
  }

  const socket = requiredEnvironment(environment, "TNL_DEV_SOCKET");
  const token = requiredEnvironment(environment, "TNL_DEV_TOKEN");
  if (!/^[a-f0-9]{64}$/.test(token)) {
    throw new Error("TNL_DEV_TOKEN is invalid");
  }

  const port = optionalPort(environment.TNL_DEV_PORT, "TNL_DEV_PORT");
  return Object.freeze({ port, socket, token });
}

/**
 * Computes the tunnel options and asks `tnl dev` for a public hostname.
 */
export async function requestTunnelAssignment(
  configuration: TnlTunnelConfiguration,
  environment: TnlDevEnvironment = process.env,
  cwd: string = process.cwd(),
): Promise<TnlTunnelAssignment | null> {
  const bootstrap = readDevEnvironment(environment);
  if (bootstrap === null) {
    return null;
  }
  if (!/^[a-z]{1,32}$/.test(configuration.framework)) {
    throw new Error("tnl framework name is invalid");
  }

  const input = configuration.options ?? {};
  const resolved =
    typeof input === "function" ? await input(await runtimeContext(cwd, environment)) : input;
  const options = validateOptions(resolved);
  const body = JSON.stringify({ protocol: 1, framework: configuration.framework, options });
  const response = await sendRequest(
    bootstrap,
    configuration.framework,
    "/v1/configure",
    body,
    200,
  );
  return validateAssignment(response, bootstrap, configuration.framework);
}

/** Selects the tunnel values that are safe to expose to application code. */
export function publicTunnelEnvironment<const Prefix extends string>(
  assignment: TnlTunnelAssignment,
  prefix: Prefix,
): TnlPublicEnvironment<Prefix> {
  return Object.freeze({
    [`${prefix}TNL_HOSTNAME`]: assignment.hostname,
    [`${prefix}TNL_TUNNEL_ID`]: assignment.tunnelID,
    [`${prefix}TNL_URL`]: assignment.publicURL,
  }) as TnlPublicEnvironment<Prefix>;
}

/** Tells `tnl dev` which port the framework is listening on. */
export async function registerTarget(assignment: TnlTunnelAssignment, port: number): Promise<void> {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("tnl target port must be between 1 and 65535");
  }
  const body = JSON.stringify({ protocol: 1, framework: assignment.framework, port });
  await sendRequest(assignment, assignment.framework, "/v1/target", body, 204);
}

function sendRequest(
  bootstrap: TnlDevBootstrap,
  framework: string,
  requestPath: string,
  body: string,
  expectedStatus: number,
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        socketPath: bootstrap.socket,
        path: requestPath,
        method: "POST",
        headers: {
          Authorization: `Bearer ${bootstrap.token}`,
          "Content-Length": Buffer.byteLength(body),
          "Content-Type": "application/json",
        },
      },
      (response) => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > maximumResponseBytes) {
            response.destroy(new Error("tnl dev returned an oversized response"));
            return;
          }
          chunks.push(chunk);
        });
        response.on("error", reject);
        response.on("end", () => {
          const data = Buffer.concat(chunks).toString("utf8").trim();
          if (response.statusCode !== expectedStatus) {
            reject(
              new Error(
                `tnl dev rejected the ${framework} request with status ${response.statusCode}${data ? `: ${data}` : ""}`,
              ),
            );
            return;
          }
          if (expectedStatus === 204) {
            if (data !== "") {
              reject(new Error("tnl dev returned an unexpected target response"));
              return;
            }
            resolve(undefined);
            return;
          }
          if (response.headers["content-type"]?.split(";", 1)[0]?.trim() !== "application/json") {
            reject(new Error("tnl dev returned a non-JSON configuration"));
            return;
          }
          try {
            resolve(JSON.parse(data));
          } catch (error) {
            reject(new Error("tnl dev returned an invalid configuration", { cause: error }));
          }
        });
      },
    );
    request.setTimeout(registrationTimeoutMilliseconds, () => {
      request.destroy(new Error("timed out configuring the target with tnl dev"));
    });
    request.on("error", reject);
    request.end(body);
  });
}

async function runtimeContext(
  cwd: string,
  environment: TnlDevEnvironment,
): Promise<TnlOptionsContext> {
  if (cwd === "") {
    throw new Error("tnl options cwd must not be empty");
  }
  const absoluteCwd = path.resolve(cwd);
  return Object.freeze({
    cwd: absoluteCwd,
    env: Object.freeze({ ...environment }),
    worktree: await resolveWorktree(absoluteCwd),
  });
}

async function resolveWorktree(cwd: string): Promise<TnlWorktree> {
  let root = cwd;
  let isGit = false;
  try {
    const { stdout } = await execFileAsync("git", ["rev-parse", "--show-toplevel"], {
      cwd,
      encoding: "utf8",
      maxBuffer: 64 * 1024,
      timeout: 5000,
    });
    const discovered = stdout.trim();
    if (discovered !== "") {
      root = path.resolve(discovered);
      isGit = true;
    }
  } catch {
    // Framework integrations also work in projects that are not Git worktrees.
  }
  const name = path.basename(root) || "worktree";
  return Object.freeze({ isGit, label: worktreeLabel(name, root), name, root });
}

function worktreeLabel(name: string, root: string): string {
  const normalized = name
    .normalize("NFKD")
    .split("")
    .filter((character) => character.charCodeAt(0) <= 0x7f)
    .join("")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  const suffix = createHash("sha256").update(root).digest("hex").slice(0, 6);
  const stem = normalized.slice(0, 56).replace(/-+$/g, "") || "worktree";
  return `${stem}-${suffix}`;
}

function validateOptions(value: unknown): TnlOptions {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("tnl options must be an object");
  }
  const record = value as Record<string, unknown>;
  const allowedKeys = new Set(["allowCurrentIP", "allowIP", "name", "server"]);
  for (const key of Object.keys(record)) {
    if (!allowedKeys.has(key)) {
      throw new Error(`unknown tnl option ${JSON.stringify(key)}`);
    }
  }

  const options: {
    allowCurrentIP?: boolean;
    allowIP?: readonly string[];
    name?: string;
    server?: string;
  } = {};
  if (record.server !== undefined) {
    options.server = boundedString(record.server, "server", 2048);
  }
  if (record.name !== undefined) {
    options.name = boundedString(record.name, "name", 253);
  }
  if (record.allowIP !== undefined) {
    if (!Array.isArray(record.allowIP) || record.allowIP.length > 64) {
      throw new Error("tnl allowIP must be an array of at most 64 entries");
    }
    options.allowIP = Object.freeze(
      record.allowIP.map((entry) => boundedString(entry, "allowIP entry", 128)),
    );
  }
  if (record.allowCurrentIP !== undefined) {
    if (typeof record.allowCurrentIP !== "boolean") {
      throw new Error("tnl allowCurrentIP must be a boolean");
    }
    options.allowCurrentIP = record.allowCurrentIP;
  }
  return Object.freeze(options);
}

function validateAssignment(
  value: unknown,
  bootstrap: TnlDevBootstrap,
  framework: string,
): TnlTunnelAssignment {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("tnl dev returned an invalid target assignment");
  }
  const assignment = value as Record<string, unknown>;
  const expectedKeys = ["hostname", "protocol", "publicURL", "tunnelID"];
  if (
    Object.keys(assignment).length !== expectedKeys.length ||
    expectedKeys.some((key) => !(key in assignment))
  ) {
    throw new Error("tnl dev returned an invalid target assignment");
  }
  if (assignment.protocol !== 1) {
    throw new Error("tnl dev returned an inconsistent target assignment");
  }
  if (!validTunnelID(assignment.tunnelID)) {
    throw new Error("tnl dev returned an invalid tunnel ID");
  }
  if (!validHostname(assignment.hostname)) {
    throw new Error("tnl dev returned an invalid public hostname");
  }
  if (!validPublicURL(assignment.publicURL, assignment.hostname)) {
    throw new Error("tnl dev returned an invalid public URL");
  }
  return Object.freeze({
    ...bootstrap,
    framework,
    hostname: assignment.hostname,
    publicURL: assignment.publicURL,
    tunnelID: assignment.tunnelID,
  });
}

function boundedString(value: unknown, name: string, maximumLength: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximumLength) {
    throw new Error(
      `tnl ${name} must be a non-empty string of at most ${maximumLength} characters`,
    );
  }
  return value;
}

function requiredEnvironment(environment: TnlDevEnvironment, name: string): string {
  const value = environment[name];
  if (typeof value !== "string" || value === "") {
    throw new Error(`${name} is required by tnl dev protocol ${protocolVersion}`);
  }
  return value;
}

function optionalPort(value: string | undefined, name: string): number | undefined {
  if (value === undefined || value === "") {
    return undefined;
  }
  if (!/^[0-9]+$/.test(value)) {
    throw new Error(`${name} must be a port between 1 and 65535`);
  }
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${name} must be a port between 1 and 65535`);
  }
  return port;
}

function validTunnelID(value: unknown): value is TnlTunnelID {
  return typeof value === "string" && /^tunnel_[a-f0-9]{32}$/.test(value);
}

function validHostname(value: unknown): value is TnlHostname {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 253 ||
    value !== value.toLowerCase()
  ) {
    return false;
  }
  return value.split(".").every(validHostnameLabel);
}

function validHostnameLabel(value: string): boolean {
  return value.length > 0 && value.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(value);
}

function validPublicURL(value: unknown, hostname: TnlHostname): value is TnlPublicURL {
  if (typeof value !== "string") {
    return false;
  }
  let parsedURL: URL;
  try {
    parsedURL = new URL(value);
  } catch {
    return false;
  }
  return (
    parsedURL.protocol === "https:" &&
    parsedURL.hostname === hostname &&
    parsedURL.port === "" &&
    parsedURL.pathname === "/" &&
    parsedURL.search === "" &&
    parsedURL.hash === "" &&
    parsedURL.username === "" &&
    parsedURL.password === ""
  );
}
