import * as http from "node:http";

const protocolVersion = "1";
const maximumResponseBytes = 4096;

type DevEnvironment = Readonly<Record<string, string | undefined>>;

export interface TnlDevSession {
  readonly hostname: string;
  readonly port?: number;
  readonly publicURL: string;
  readonly socket: string;
  readonly token: string;
  readonly tunnelID: string;
}

export interface RegisteredTnlDevSession extends TnlDevSession {
  readonly port: number;
}

export function readDevEnvironment(
  environment: DevEnvironment = process.env,
): TnlDevSession | null {
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
  const tunnelID = requiredEnvironment(environment, "TNL_TUNNEL_ID");
  const hostname = requiredEnvironment(environment, "TNL_PUBLIC_HOSTNAME");
  const publicURL = requiredEnvironment(environment, "TNL_PUBLIC_URL");
  if (!/^[a-f0-9]{64}$/.test(token)) {
    throw new Error("TNL_DEV_TOKEN is invalid");
  }
  if (!/^tunnel_[a-f0-9]{32}$/.test(tunnelID)) {
    throw new Error("TNL_TUNNEL_ID is invalid");
  }
  if (!validHostname(hostname)) {
    throw new Error("TNL_PUBLIC_HOSTNAME is invalid");
  }

  let parsedURL: URL;
  try {
    parsedURL = new URL(publicURL);
  } catch {
    throw new Error("TNL_PUBLIC_URL is invalid");
  }
  if (
    parsedURL.protocol !== "https:" ||
    parsedURL.hostname !== hostname ||
    parsedURL.port !== "" ||
    parsedURL.pathname !== "/" ||
    parsedURL.search !== "" ||
    parsedURL.hash !== "" ||
    parsedURL.username !== "" ||
    parsedURL.password !== ""
  ) {
    throw new Error("TNL_PUBLIC_URL is invalid");
  }

  const port = optionalPort(environment.TNL_DEV_PORT, "TNL_DEV_PORT");
  return Object.freeze({ hostname, port, publicURL, socket, token, tunnelID });
}

export async function registerTarget(
  framework: string,
  port: number,
  environment: DevEnvironment = process.env,
): Promise<RegisteredTnlDevSession | null> {
  const session = readDevEnvironment(environment);
  if (session === null) {
    return null;
  }
  if (!/^[a-z]{1,32}$/.test(framework)) {
    throw new Error("tnl framework name is invalid");
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("tnl target port must be between 1 and 65535");
  }

  const body = JSON.stringify({ protocol: 1, framework, port });
  await new Promise<void>((resolve, reject) => {
    const request = http.request(
      {
        socketPath: session.socket,
        path: "/v1/target",
        method: "POST",
        headers: {
          Authorization: `Bearer ${session.token}`,
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
          if (response.statusCode === 204) {
            resolve();
            return;
          }
          const detail = Buffer.concat(chunks).toString("utf8").trim();
          reject(
            new Error(
              `tnl dev rejected the ${framework} target with status ${response.statusCode}${detail ? `: ${detail}` : ""}`,
            ),
          );
        });
      },
    );
    request.setTimeout(5000, () => {
      request.destroy(new Error("timed out registering the target with tnl dev"));
    });
    request.on("error", reject);
    request.end(body);
  });
  return Object.freeze({ ...session, port });
}

function requiredEnvironment(environment: DevEnvironment, name: string): string {
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

function validHostname(value: string): boolean {
  if (value.length === 0 || value.length > 253 || value !== value.toLowerCase()) {
    return false;
  }
  return value.split(".").every((label) => {
    return (
      label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
    );
  });
}
