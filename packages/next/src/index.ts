import {
  publicTunnelEnvironment,
  readDevEnvironment,
  registerTarget,
  requestTunnelAssignment,
} from "@tnldotdev/dev";
import type { TnlOptionsInput } from "@tnldotdev/dev";
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

export type { TnlOptions, TnlOptionsContext, TnlOptionsInput, TnlWorktree } from "@tnldotdev/dev";

/**
 * Adds tnl support to a Next.js development server. It preserves the original
 * Next.js configuration and does nothing when started without `tnl dev`.
 */
export function withTnl(
  config: NextConfigInput = {},
  options: TnlOptionsInput = {},
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
    const port = parsePort(process.env.PORT, "PORT");
    if (session.port !== undefined && session.port !== port) {
      throw new Error(
        `Next.js listened on port ${port}, but tnl dev --port requires ${session.port}`,
      );
    }
    const assignment = await requestTunnelAssignment({ framework: "next", options });
    if (assignment === null) {
      return nextConfig;
    }
    await registerTarget(assignment, port);
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
