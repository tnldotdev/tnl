import {
  canonicalLoopbackTarget,
  parseListenerPort,
  runtimePayload,
  serviceHostnames,
} from "./internal/dev.js";
import type { NextConfig } from "next";
import { TnlError } from "./errors.js";
import { prepareService, reportFrameworkTarget, type PrepareOptions } from "./internal/app.js";

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

/** configures a Next.js development server to register its listener and add project metadata. */
export function withTnl(
  config: NextConfigInput = {},
  options: PrepareOptions = {},
): NextConfigFactory {
  return async function tnlNextConfig(phase, context) {
    const resolved = typeof config === "function" ? await config(phase, context) : await config;
    const nextConfig = resolved ?? {};
    if (phase !== developmentServerPhase) {
      return nextConfig;
    }

    const allowedDevOrigins = nextConfig.allowedDevOrigins ?? [];
    if (
      !Array.isArray(allowedDevOrigins) ||
      !allowedDevOrigins.every((origin) => typeof origin === "string")
    ) {
      throw new TnlError("sdk.configuration_invalid");
    }
    const target = nextTarget(process.env);
    const assignment = await prepareService(options, "next");
    // supported Next versions set this origin from their bound HTTP listener
    // before loading configuration. PORT alone is never a registration.
    await reportFrameworkTarget(assignment, target);

    return injectRuntime(
      {
        ...nextConfig,
        allowedDevOrigins: unique([
          ...allowedDevOrigins,
          ...serviceHostnames({
            hostname: assignment.hostname,
            project: assignment,
            service: assignment.service,
          }),
        ]),
      },
      runtimePayload(assignment, true),
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
