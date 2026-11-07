import { serviceHostnames, serializeRuntimePayload } from "./internal/project/runtime.js";
import { canonicalLoopbackTarget, parseListenerPort } from "./internal/publisher/target.js";
import type { NextConfig } from "next";
import { NextResponse, type NextRequest } from "next/server.js";
import { TnlError } from "./errors.js";
import {
  prepareService,
  reportFrameworkTarget,
  proxyTokenFor,
  type PrepareOptions,
} from "./internal/publisher/app.js";
import { operation } from "./internal/tracing.js";
import * as z from "zod";
import { parseValue } from "./internal/validation.js";
import { verifyProxyHeaders } from "./internal/publisher/proxy_request.js";

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

    const allowedDevOrigins = parseValue(
      allowedDevOriginsSchema,
      nextConfig.allowedDevOrigins ?? [],
      "sdk.configuration_invalid",
    );
    const target = nextTarget(process.env);
    const assignment = await operation("next.register", async () => {
      const assignment = await prepareService(options, "next");
      // supported Next versions set this origin from their bound HTTP listener
      // before loading configuration. PORT alone is never a registration.
      await reportFrameworkTarget(assignment, target);
      return assignment;
    });

    // Next's proxy runs in a server process, not in the config callback.
    // neither value is placed in Next's browser-visible config.env payload.
    process.env.__TNL_PRIVATE_APP_PROXY_TOKEN = proxyTokenFor(assignment);
    process.env.__TNL_PRIVATE_APP_PROXY_HOSTS = JSON.stringify(
      serviceHostnames({
        hostname: assignment.hostname,
        project: assignment,
        service: assignment.service,
      }),
    );

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

/** place `export { tnlProxy as proxy } from "@tnldotdev/tnl/next"` in proxy.ts. */
export function tnlProxy(request: NextRequest): NextResponse {
  if (process.env.NODE_ENV !== "development") return NextResponse.next();
  const token = process.env.__TNL_PRIVATE_APP_PROXY_TOKEN;
  const hosts = process.env.__TNL_PRIVATE_APP_PROXY_HOSTS;
  if (token === undefined || hosts === undefined) return new NextResponse(null, { status: 503 });
  const headers = new Headers(request.headers);
  let parsed: unknown;
  try {
    parsed = JSON.parse(hosts);
  } catch {
    return new NextResponse(null, { status: 503 });
  }
  if (!Array.isArray(parsed) || !parsed.every((host) => typeof host === "string")) {
    return new NextResponse(null, { status: 503 });
  }
  if (!verifyProxyHeaders(headers, token, new Set<string>(parsed))) {
    return new NextResponse(null, { status: 403 });
  }
  return NextResponse.next({ request: { headers } });
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
