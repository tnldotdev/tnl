import {
  publicTunnelEnvironment,
  readDevEnvironment,
  registerLocalPort,
  requestTunnelAssignment,
} from "@tnldotdev/dev";
import type { TnlTunnelOptionsInput } from "@tnldotdev/dev";
import type { NextConfig } from "next";

const developmentServerPhase = "phase-development-server";

export interface NextConfigContext {
  /** The default Next.js configuration. */
  readonly defaultConfig: NextConfig;
}

/** A function that returns Next.js configuration. */
export type NextConfigFactory = (
  phase: string,
  context: NextConfigContext,
) => NextConfig | Promise<NextConfig>;

type NextConfigInput = NextConfig | Promise<NextConfig> | NextConfigFactory;

export type {
  TnlTunnelOptions,
  TnlTunnelOptionsContext,
  TnlTunnelOptionsInput,
  TnlWorktree,
} from "@tnldotdev/dev";

/**
 * Adds tnl support to a Next.js development server. It preserves the original
 * Next.js configuration and does nothing when started without `tnl dev`.
 */
export function withTnl(
  config: NextConfigInput = {},
  options: TnlTunnelOptionsInput = {},
): NextConfigFactory {
  return async function tnlNextConfig(phase, context) {
    const resolved = typeof config === "function" ? await config(phase, context) : await config;
    const nextConfig = resolved ?? {};
    const session = readDevEnvironment();
    if (phase !== developmentServerPhase || session === null) {
      return nextConfig;
    }

    const allowedDevOrigins = nextConfig.allowedDevOrigins ?? [];
    if (!Array.isArray(allowedDevOrigins)) {
      throw new Error("Next.js allowedDevOrigins must be an array when used with tnl");
    }
    const port = session.port ?? nextPort(process.env, process.argv);
    const assignment = await requestTunnelAssignment({ framework: "next", options });
    if (assignment === null) {
      return nextConfig;
    }
    await registerLocalPort(assignment, port);
    return {
      ...nextConfig,
      allowedDevOrigins: unique([...allowedDevOrigins, assignment.hostname]),
      env: {
        ...nextConfig.env,
        ...publicTunnelEnvironment(assignment, "NEXT_PUBLIC_"),
      },
    };
  };
}

function nextPort(environment: NodeJS.ProcessEnv, arguments_: readonly string[]): number {
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument.startsWith("--port=")) {
      return parsePort(argument.slice("--port=".length), "--port");
    }
    if (argument === "--port" || argument === "-p") {
      return parsePort(arguments_[index + 1], argument);
    }
  }
  if (environment.PORT !== undefined && environment.PORT !== "") {
    return parsePort(environment.PORT, "PORT");
  }
  return 3000;
}

function parsePort(value: string | undefined, source: string): number {
  if (typeof value !== "string" || !/^[0-9]+$/.test(value)) {
    throw new Error(`${source} must be a port between 1 and 65535`);
  }
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${source} must be a port between 1 and 65535`);
  }
  return port;
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
}
