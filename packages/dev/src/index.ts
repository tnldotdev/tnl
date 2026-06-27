import * as http from "node:http";
import {
  gte,
  hostname,
  int,
  literal,
  lowercase,
  lte,
  minLength,
  object,
  optional,
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

/** Tunnel configuration supplied by a framework integration. */
export interface TnlTunnelConfiguration {
  /** Lowercase framework name, such as `vite` or `next`. */
  readonly framework: string;
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
 * Asks `tnl dev` for a public hostname.
 */
export async function requestTunnelAssignment(
  configuration: TnlTunnelConfiguration,
  environment: TnlDevEnvironment = process.env,
): Promise<TnlTunnelAssignment | null> {
  const bootstrap = readDevEnvironment(environment);
  if (bootstrap === null) {
    return null;
  }
  parseSchema(frameworkSchema, configuration.framework);

  const body = JSON.stringify({ protocol: 1, framework: configuration.framework });
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
