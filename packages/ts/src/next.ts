import { serviceHostnames, serializeRuntimePayload } from "./internal/project/runtime.js";
import { canonicalLoopbackTarget, parseListenerPort } from "./internal/publisher/target.js";
import type { NextConfig } from "next";
import { TnlError } from "./errors.js";
import {
  frameworkOptions,
  localRuntimePayload,
  prepareFramework,
  type FrameworkOptions,
} from "./internal/publisher/framework.js";
import { operation } from "./internal/tracing.js";
import * as z from "zod";
import { parseValue } from "./internal/validation.js";

const developmentServerPhase = "phase-development-server";
const runtimeEnvironmentName = "TNL_PROJECT_RUNTIME";
const allowedDevOriginsSchema = z.array(z.string());

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
export type { FrameworkOptions } from "./internal/publisher/framework.js";

/** configures a Next.js development server to register its listener and add project metadata. */
export function withTnl(
  config: NextConfigInput = {},
  options: FrameworkOptions = {},
): NextConfigFactory {
  return async function tnlNextConfig(phase, context) {
    const resolved = typeof config === "function" ? await config(phase, context) : await config;
    const nextConfig = resolved ?? {};
    if (phase !== developmentServerPhase) {
      return nextConfig;
    }
    if (frameworkOptions(options).preview === false) {
      return injectRuntime(nextConfig, localRuntimePayload);
    }

    const allowedDevOrigins = parseValue(
      allowedDevOriginsSchema,
      nextConfig.allowedDevOrigins ?? [],
      "sdk.configuration_invalid",
    );
    const target = nextTarget(process.env);
    // supported Next versions report the bound listener before loading config.
    // PORT alone is never a registration.
    const assignment = await operation("next.register", () =>
      prepareFramework(options, "next", target),
    );
    if (assignment === null) return injectRuntime(nextConfig, localRuntimePayload);

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
      serializeRuntimePayload(assignment, true),
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
  const port = parseListenerPort(origin.port);
  const reportedPort = environment.PORT;
  if (reportedPort !== undefined && parseListenerPort(reportedPort) !== port) {
    throw new TnlError("sdk.target_invalid");
  }
  return canonicalLoopbackTarget(origin.hostname, port);
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
}
