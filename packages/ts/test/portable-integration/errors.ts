import { FixtureAssertionError } from "./fixture.ts";
import * as z from "zod";

// the tnlwasmtest artifact records only fixed Go type names and failure facts.
// validate that boundary again before returning it from the fixture Worker.
export const portableDiagnosticsSchema = z
  .array(
    z.object({
      types: z.array(z.string().regex(/^[a-zA-Z0-9_.*]{1,120}$/)).max(64),
      resets: z
        .array(z.object({ remote: z.boolean(), code: z.number().int().nonnegative() }))
        .max(64),
      canceled: z.boolean(),
      deadline: z.boolean(),
      closed: z.boolean(),
      pipe_closed: z.boolean(),
      eof: z.boolean(),
      terminal_failed: z.boolean(),
      service_unavailable: z.boolean(),
      reason: z
        .string()
        .regex(/^[a-z_.]{1,100}$/)
        .optional(),
    }),
  )
  .max(16);

export function portableDiagnostics(): z.output<typeof portableDiagnosticsSchema> | undefined {
  const result = portableDiagnosticsSchema.safeParse(
    Reflect.get(globalThis, "__tnlWasmFixtureDiagnostics"),
  );
  return result.success ? result.data : undefined;
}

export type Phase =
  | "http"
  | "tcp"
  | "tcp-close"
  | "mysql"
  | "kubernetes"
  | "postgres"
  | "workload"
  | "carrier-loss"
  | "close-open"
  | "close-deployment"
  | "close-read"
  | "close-reject"
  | "close-stream"
  | "isolation"
  | "cleanup";

export class PortableSmokeError extends Error {
  readonly phase: Phase;
  readonly code: string;
  readonly detail: string | undefined;

  constructor(phase: Phase, error: unknown) {
    const code =
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      typeof error.code === "string" &&
      /^sdk\.[a-z_]{1,60}$/.test(error.code)
        ? error.code
        : error instanceof FixtureAssertionError
          ? "fixture.assertion_failed"
          : "fixture.operation_failed";
    super(`portable SDK ${phase} failed (${code})`);
    this.phase = phase;
    this.code = code;
    this.detail =
      error instanceof FixtureAssertionError
        ? error.message
        : safeErrorKinds(error).slice(0, 8).join(", ").slice(0, 300);
  }
}

// report bounded error kinds, never host/driver messages or private input.
function safeErrorKinds(error: unknown, depth = 0): string[] {
  if (depth >= 3) return ["nested_error"];
  if (error instanceof AggregateError)
    return error.errors.slice(0, 8).flatMap((child: unknown) => safeErrorKinds(child, depth + 1));
  if (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    typeof error.code === "string" &&
    /^sdk\.[a-z_]{1,60}$/.test(error.code)
  )
    return [error.code];
  if (error instanceof TypeError) return ["TypeError"];
  if (error instanceof RangeError) return ["RangeError"];
  if (error instanceof DOMException) return ["DOMException"];
  return ["unknown_error"];
}
