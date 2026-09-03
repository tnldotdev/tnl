import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import * as http from "node:http";
import path from "node:path";
import { promisify } from "node:util";
import {
  array,
  boolean,
  gte,
  hostname,
  int,
  literal,
  lowercase,
  lte,
  maxLength,
  minLength,
  object,
  optional,
  readonly as readonlySchema,
  refine,
  regex,
  string,
  stringFormat,
  url,
  type output,
  type ZodMiniType,
} from "zod/mini";

const protocolVersion = "1";
const maximumResponseBytes = 4096;
const registrationTimeoutMilliseconds = 10 * 60 * 1000;
const execFileAsync = promisify(execFile);

declare const tnlHostnameBrand: unique symbol;
declare const tnlPublicURLBrand: unique symbol;
declare const tnlTunnelIDBrand: unique symbol;

const frameworkError = "tnl framework name is invalid";
const localPortError = "tnl local port must be between 1 and 65535";
const publicURLError = "tnl dev returned an invalid public URL";
const environmentPortError = "TNL_DEV_PORT must be a port between 1 and 65535";
const socketRequiredError = `TNL_DEV_SOCKET is required by tnl dev protocol ${protocolVersion}`;
const tokenRequiredError = `TNL_DEV_TOKEN is required by tnl dev protocol ${protocolVersion}`;

const frameworkSchema = string(frameworkError).check(regex(/^[a-z]{1,32}$/, frameworkError));
const localPortSchema = portSchema(localPortError);
const devEnvironmentSchema = object({
  TNL_DEV_SOCKET: string(socketRequiredError).check(minLength(1, socketRequiredError)),
  TNL_DEV_TOKEN: string(tokenRequiredError).check(
    minLength(1, tokenRequiredError),
    regex(/^[a-f0-9]{64}$/, "TNL_DEV_TOKEN is invalid"),
  ),
  TNL_DEV_PORT: optional(
    string(environmentPortError).check(
      refine(
        (value) =>
          value === "" || (/^[0-9]+$/.test(value) && Number(value) >= 1 && Number(value) <= 65535),
        environmentPortError,
      ),
    ),
  ),
});

const optionStringSchema = (name: string, maximumLength: number) => {
  const error = `tnl ${name} must be a non-empty string of at most ${maximumLength} characters`;
  return string(error).check(
    refine((value) => value.length > 0 && value.length <= maximumLength, error),
  );
};
const allowIPError = "tnl allowIP must be an array of at most 64 entries";
const tunnelOptionsSchema = readonlySchema(
  object(
    {
      allowCurrentIP: optional(boolean("tnl allowCurrentIP must be a boolean")),
      allowIP: optional(
        readonlySchema(
          array(optionStringSchema("allowIP entry", 128), allowIPError).check(
            maxLength(64, allowIPError),
          ),
        ),
      ),
      controlURL: optional(optionStringSchema("controlURL", 2048)),
      host: optional(optionStringSchema("host", 253)),
    },
    "tnl options must be an object",
  ),
);

const hostnameError = "tnl dev returned an invalid public hostname";
const hostnameSchema = hostname(hostnameError).check(
  lowercase(hostnameError),
  refine((value) => !value.endsWith("."), hostnameError),
);
const tunnelAssignmentSchema = object(
  {
    hostname: hostnameSchema,
    protocol: literal(1, "tnl dev returned an inconsistent tunnel assignment"),
    publicURL: url(publicURLError),
    tunnelID: stringFormat(
      "tnl-tunnel-id",
      /^tunnel_[a-f0-9]{32}$/,
      "tnl dev returned an invalid tunnel ID",
    ),
  },
  "tnl dev returned an invalid tunnel assignment",
).check(
  refine(({ hostname, publicURL }) => {
    const parsedURL = new URL(publicURL);
    return (
      parsedURL.origin === `https://${hostname}` &&
      parsedURL.pathname === "/" &&
      !parsedURL.search &&
      !parsedURL.hash &&
      !parsedURL.username &&
      !parsedURL.password
    );
  }, publicURLError),
);

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
export interface TnlTunnelOptions {
  /** Control server URL to use. `--server` or `TNL_SERVER` overrides this value. */
  readonly controlURL?: string;
  /**
   * Public hostname to use. This may be a managed hostname or a child hostname
   * under one you own. `--host` or `TNL_HOST` overrides this value.
   */
  readonly host?: string;
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
export interface TnlTunnelOptionsContext {
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
export type TnlTunnelOptionsInput =
  | TnlTunnelOptions
  | ((context: TnlTunnelOptionsContext) => TnlTunnelOptions | Promise<TnlTunnelOptions>);

/** Tunnel configuration supplied by a framework integration. */
export interface TnlTunnelConfiguration {
  /** Lowercase framework name, such as `vite` or `next`. */
  readonly framework: string;
  /** Options supplied by the project. */
  readonly options?: TnlTunnelOptionsInput;
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

  const values = parseSchema(devEnvironmentSchema, environment);
  const port = values.TNL_DEV_PORT ? Number(values.TNL_DEV_PORT) : undefined;
  return Object.freeze({ port, socket: values.TNL_DEV_SOCKET, token: values.TNL_DEV_TOKEN });
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
  parseSchema(frameworkSchema, configuration.framework);

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

/** Tells `tnl dev` which local port the framework is listening on. */
export async function registerLocalPort(
  assignment: TnlTunnelAssignment,
  port: number,
): Promise<void> {
  parseSchema(localPortSchema, port);
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
): Promise<TnlTunnelOptionsContext> {
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

function validateOptions(value: unknown): TnlTunnelOptions {
  return parseSchema(tunnelOptionsSchema, value);
}

function validateAssignment(
  value: unknown,
  bootstrap: TnlDevBootstrap,
  framework: string,
): TnlTunnelAssignment {
  const assignment = parseSchema(tunnelAssignmentSchema, value);
  return Object.freeze({
    ...bootstrap,
    framework,
    hostname: assignment.hostname as TnlHostname,
    publicURL: assignment.publicURL as TnlPublicURL,
    tunnelID: assignment.tunnelID as TnlTunnelID,
  });
}

function parseSchema<T extends ZodMiniType>(schema: T, value: unknown): output<T> {
  const result = schema.safeParse(value);
  if (!result.success) {
    throw new Error(result.error.issues[0]?.message ?? "invalid tnl value", {
      cause: result.error,
    });
  }
  return result.data;
}

function portSchema(error: string) {
  return int(error).check(gte(1, error), lte(65535, error));
}
