import {
  canonicalLoopbackTarget,
  parseListenerPort,
  readDevelopmentContext,
  registerLocalTarget,
  requestTunnelAssignment,
  runtimePayload,
} from "./internal/dev.js";
import type { NextConfig } from "next";
import { TnlError } from "./errors.js";

const developmentServerPhase = "phase-development-server";
const runtimeEnvironmentName = "TNL_PROJECT_RUNTIME";

export interface NextConfigContext {
  /** The default Next.js configuration. */
  readonly defaultConfig: NextConfig;
}

/** A function that returns Next.js configuration. */
export type NextConfigFactory = (
  phase: string,
  context: NextConfigContext,
) => NextConfig | Promise<NextConfig>;

export type NextConfigInput = NextConfig | Promise<NextConfig> | NextConfigFactory;

/** Configures a Next.js development server for `tnl dev` and adds project metadata. */
export function withTnl(config: NextConfigInput = {}, ...extra: never[]): NextConfigFactory {
  if (extra.length !== 0) {
    throw new TnlError("sdk.configuration_invalid");
  }
  return async function tnlNextConfig(phase, context) {
    const resolved = typeof config === "function" ? await config(phase, context) : await config;
    const nextConfig = resolved ?? {};
    if (phase !== developmentServerPhase) {
      return nextConfig;
    }

    const development = readDevelopmentContext();
    if (development.bootstrap === null) {
      if (development.localProject === null) {
        return nextConfig;
      }
      return injectRuntime(nextConfig, runtimePayload(development.localProject, false));
    }

    const allowedDevOrigins = nextConfig.allowedDevOrigins ?? [];
    if (
      !Array.isArray(allowedDevOrigins) ||
      !allowedDevOrigins.every((origin) => typeof origin === "string")
    ) {
      throw new TnlError("sdk.configuration_invalid");
    }
    const target = nextTarget(process.env);
    const assignment = await requestTunnelAssignment("next", development.bootstrap);
    await registerLocalTarget(assignment, target);

    return injectRuntime(
      {
        ...nextConfig,
        allowedDevOrigins: unique([...allowedDevOrigins, assignment.hostname]),
      },
      runtimePayload(assignment.project, true),
    );
  };
}

function injectRuntime(config: NextConfig, payload: string): NextConfig {
  return {
    ...config,
    env: {
      ...config.env,
      [runtimeEnvironmentName]: payload,
    },
  };
}

function nextTarget(environment: NodeJS.ProcessEnv): `http://${string}` {
  // Next 16.3.4 binds and sets this origin before loading next.config, so it is authoritative.
  const value = environment.__NEXT_PRIVATE_ORIGIN;
  if (value === undefined) {
    throw new TnlError("sdk.target_invalid");
  }
  let origin: URL;
  try {
    origin = new URL(value);
    if (
      origin.protocol !== "http:" ||
      origin.username !== "" ||
      origin.password !== "" ||
      origin.pathname !== "/" ||
      origin.search !== "" ||
      origin.hash !== "" ||
      origin.port === ""
    ) {
      throw new TnlError("sdk.target_invalid");
    }
  } catch (error) {
    throw new TnlError("sdk.target_invalid", { cause: error });
  }
  const port = parseListenerPort(origin.port, "Next.js listener");
  const reportedPort = environment.PORT;
  if (reportedPort !== undefined && parseListenerPort(reportedPort, "PORT") !== port) {
    throw new TnlError("sdk.target_invalid");
  }
  return canonicalLoopbackTarget(origin.hostname, port);
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
}
