// this protocol belongs only to the installed-package fixture. never serialize
// an Error, its cause, or arbitrary child output at the reporting boundary.
export const fixtureReportPrefix = "tnl-drizzle-fixture ";
const childReportPrefix = "tnl-drizzle-child ";
export const fixtureStages = [
  "fixture preparation",
  "native packaging",
  "sdk packaging",
  "dependency installation",
  "filesystem preparation",
  "installed settings verifier",
  "drizzle migration",
  "post-migration preparation",
  "post-migration query",
  "database drivers",
  "native runtime",
  "consumer cleanup",
] as const;
export type FixtureStage = (typeof fixtureStages)[number];

const machineCodes = [
  "sdk.authentication_required",
  "sdk.configuration_invalid",
  "sdk.connection_unavailable",
  "sdk.connection_unprepared",
  "sdk.native_invalid",
  "sdk.native_missing",
  "sdk.native_unsupported",
  "sdk.response_invalid",
  "ERR_ASSERTION",
  "08001",
  "08006",
  "23505",
  "28P01",
  "3D000",
  "42501",
  "42601",
  "42710",
  "42P01",
  "53300",
  "57P01",
] as const;
const signals = [
  "SIGABRT",
  "SIGHUP",
  "SIGINT",
  "SIGKILL",
  "SIGPIPE",
  "SIGQUIT",
  "SIGSEGV",
  "SIGTERM",
] as const;
type Metadata = {
  cause_status: "reported" | "unknown" | "truncated";
  error_code?: (typeof machineCodes)[number];
  exit_code?: number;
  errno?: number;
  signal?: (typeof signals)[number];
  killed?: boolean;
};
type FixtureReport = Metadata & {
  code: "fixture.installed_drizzle_failed";
  stage: FixtureStage;
  elapsed_ms: number | null;
};

function member<T extends string>(values: readonly T[], value: unknown): value is T {
  return typeof value === "string" && values.some((entry) => entry === value);
}
function integer(value: unknown, min: number, max: number): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= min && value <= max;
}
function data(value: unknown, key: string): unknown {
  if (typeof value !== "object" || value === null) return undefined;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor !== undefined && "value" in descriptor ? descriptor.value : undefined;
  } catch {
    return undefined;
  }
}

function projectCause(cause: unknown): Metadata {
  const result: Metadata = { cause_status: "unknown" };
  const code = data(cause, "code");
  if (member(machineCodes, code)) {
    result.error_code = code;
    result.cause_status = "reported";
  } else if (integer(code, 0, 255)) result.exit_code = code;
  const errno = data(cause, "errno");
  if (integer(errno, -4095, 0)) result.errno = errno;
  const signal = data(cause, "signal");
  if (member(signals, signal)) result.signal = signal;
  const killed = data(cause, "killed");
  if (typeof killed === "boolean") result.killed = killed;
  // never walk a nested cause or invoke an accessor, even for an Error.
  if (typeof cause === "object" && cause !== null) {
    try {
      if (Object.getOwnPropertyDescriptor(cause, "cause") !== undefined)
        result.cause_status = "truncated";
    } catch {
      result.cause_status = "unknown";
    }
  }
  return result;
}

// bound bytes, fields, and depth before JSON.parse. the child protocol is flat;
// arrays, nested objects, duplicate fields, and extra properties are not accepted.
function flatRecord(text: string): Record<string, unknown> | undefined {
  if (Buffer.byteLength(text) > 1024 || !text.startsWith("{") || !text.endsWith("}"))
    return undefined;
  let quoted = false;
  let escaped = false;
  let fields = 0;
  for (let index = 1; index < text.length - 1; index++) {
    const character = text[index];
    if (quoted) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') quoted = false;
    } else if (character === '"') quoted = true;
    else if (character === "{" || character === "}" || character === "[" || character === "]")
      return undefined;
    else if (character === ":" && ++fields > 7) return undefined;
  }
  if (quoted) return undefined;
  try {
    const value: unknown = JSON.parse(text);
    if (typeof value !== "object" || value === null || Object.keys(value).length !== fields)
      return undefined;
    return value as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

function childMetadata(record: Record<string, unknown>): Metadata | undefined {
  const allowed = ["code", "cause_status", "error_code", "exit_code", "errno", "signal", "killed"];
  if (
    Object.keys(record).some((key) => !allowed.includes(key)) ||
    record.code !== "fixture.drizzle_child_failed" ||
    !["reported", "unknown", "truncated"].includes(String(record.cause_status)) ||
    (record.error_code !== undefined && !member(machineCodes, record.error_code)) ||
    (record.cause_status === "reported" && record.error_code === undefined) ||
    (record.exit_code !== undefined && !integer(record.exit_code, 0, 255)) ||
    (record.errno !== undefined && !integer(record.errno, -4095, 0)) ||
    (record.signal !== undefined && !member(signals, record.signal)) ||
    (record.killed !== undefined && typeof record.killed !== "boolean")
  )
    return undefined;
  const { code: _code, ...metadata } = record;
  return metadata as Metadata;
}

export function readChildFailure(output: unknown): Metadata | undefined {
  if (typeof output !== "string") return undefined;
  // only inspect the first 8 KiB and 32 lines, accepting at most one record.
  // all limits are diagnostic-only and explicitly mark incomplete evidence.
  const prefix = output.slice(0, 8192);
  const bytes = Buffer.from(prefix);
  let truncated = output.length > prefix.length || bytes.length > 8192;
  const lines = bytes.subarray(0, 8192).toString("utf8").split("\n", 33);
  truncated ||= lines.length > 32;
  let result: Metadata | undefined;
  let records = 0;
  for (const line of lines.slice(0, 32)) {
    if (!line.startsWith(childReportPrefix)) continue;
    if (++records > 1) return { cause_status: "truncated" };
    const text = line.slice(childReportPrefix.length);
    if (Buffer.byteLength(text) > 1024) return { cause_status: "truncated" };
    const record = flatRecord(text);
    result = record === undefined ? undefined : childMetadata(record);
    if (result === undefined) return { cause_status: "unknown" };
  }
  return truncated ? { ...result, cause_status: "truncated" } : result;
}

export class InstalledDrizzleFailure extends Error {
  readonly #report: FixtureReport;
  #cleanup: InstalledDrizzleFailure | undefined;
  constructor(stage: FixtureStage, elapsed: number | null, cause: unknown) {
    super("installed package verification failed", { cause });
    const metadata = projectCause(cause);
    const child = readChildFailure(data(cause, "stderr"));
    this.#report = Object.freeze({
      ...metadata,
      ...child,
      // the execFile error owns the actual child exit/signal, not its report.
      ...(metadata.exit_code === undefined ? {} : { exit_code: metadata.exit_code }),
      ...(metadata.errno === undefined ? {} : { errno: metadata.errno }),
      ...(metadata.signal === undefined ? {} : { signal: metadata.signal }),
      ...(metadata.killed === undefined ? {} : { killed: metadata.killed }),
      cause_status:
        metadata.cause_status === "truncated" || child?.cause_status === "truncated"
          ? "truncated"
          : (child?.cause_status ?? metadata.cause_status),
      code: "fixture.installed_drizzle_failed",
      stage: member(fixtureStages, stage) ? stage : "fixture preparation",
      elapsed_ms: integer(elapsed, 0, Number.MAX_SAFE_INTEGER) ? elapsed : null,
    });
  }

  static capture(
    stage: FixtureStage,
    elapsed: number | null,
    cause: unknown,
  ): InstalledDrizzleFailure {
    try {
      if (cause instanceof InstalledDrizzleFailure) {
        void cause.#report;
        return cause;
      }
    } catch {
      // a forged prototype has no owned report.
    }
    return new InstalledDrizzleFailure(stage, elapsed, cause);
  }

  get cleanup(): InstalledDrizzleFailure | undefined {
    return this.#cleanup;
  }

  withCleanup(cleanup: InstalledDrizzleFailure): this {
    this.#cleanup = cleanup;
    return this;
  }

  static reports(cause: unknown): FixtureReport[] {
    const failure = InstalledDrizzleFailure.capture("fixture preparation", null, cause);
    // report at most the original failure and its one owned cleanup failure.
    return failure.#cleanup ? [failure.#report, failure.#cleanup.#report] : [failure.#report];
  }
}

export async function fixtureStep<T>(
  stage: FixtureStage,
  action: () => T | Promise<T>,
): Promise<T> {
  const started = performance.now();
  try {
    return await action();
  } catch (cause) {
    throw InstalledDrizzleFailure.capture(stage, Math.round(performance.now() - started), cause);
  }
}

export function formatFixtureFailure(cause: unknown): string {
  return InstalledDrizzleFailure.reports(cause)
    .map((report) => fixtureReportPrefix + JSON.stringify(report) + "\n")
    .join("");
}

export function observeDrizzleConfig<T>(action: () => T): T {
  try {
    return action();
  } catch (cause) {
    process.stderr.write(formatChildFailure(cause));
    throw cause;
  }
}

export function formatChildFailure(cause: unknown): string {
  return (
    childReportPrefix +
    JSON.stringify({ code: "fixture.drizzle_child_failed", ...projectCause(cause) }) +
    "\n"
  );
}
