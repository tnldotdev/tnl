import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

export type ToolErrorCode =
  | "tool.input_invalid"
  | "tool.process_failed"
  | "tool.validation_failed"
  | "tool.interrupted"
  | "tool.unexpected";
const definitions: Record<
  ToolErrorCode,
  {
    class: "invalid" | "unavailable" | "internal";
    retry: "never" | "after_change";
    message: string;
  }
> = {
  "tool.input_invalid": {
    class: "invalid",
    retry: "after_change",
    message: "tool input is invalid; check the arguments and source files",
  },
  "tool.process_failed": {
    class: "unavailable",
    retry: "after_change",
    message:
      "a required process failed; check local prerequisites and service health before retrying",
  },
  "tool.validation_failed": {
    class: "invalid",
    retry: "after_change",
    message: "validation failed; check the selected artifact, source, or workload result",
  },
  "tool.interrupted": {
    class: "unavailable",
    retry: "never",
    message: "the operation was interrupted",
  },
  "tool.unexpected": {
    class: "internal",
    retry: "never",
    message:
      "the tooling operation failed unexpectedly; check prerequisites and report the failure if it continues",
  },
};
export class ToolError extends Error {
  readonly code: ToolErrorCode;
  readonly class: "invalid" | "unavailable" | "internal";
  readonly retry: "never" | "after_change";
  constructor(code: ToolErrorCode, options?: ErrorOptions) {
    super(definitions[code].message, options);
    this.name = "ToolError";
    this.code = code;
    this.class = definitions[code].class;
    this.retry = definitions[code].retry;
  }
}
export function toolFailure(
  error: unknown,
  fallback: ToolErrorCode = "tool.unexpected",
): ToolError {
  return error instanceof ToolError ? error : new ToolError(fallback, { cause: error });
}
export function safeToolMessage(
  error: unknown,
  fallback: ToolErrorCode = "tool.unexpected",
): string {
  const failure = toolFailure(error, fallback);
  return `${failure.code}: ${definitions[failure.code].message}`;
}

// only the directly executed tool owns process-level reporting. importing its
// helpers into tests or another tool must not install global handlers.
let installed = false;
export function installToolFailureHandler(
  meta: Pick<ImportMeta, "url">,
  fallback: ToolErrorCode = "tool.unexpected",
): void {
  if (process.argv[1] === undefined || path.resolve(process.argv[1]) !== fileURLToPath(meta.url))
    return;
  if (installed) return;
  installed = true;
  process.once("uncaughtException", (error) => {
    console.error(
      `tnl tooling: ${path.basename(fileURLToPath(meta.url))}: ${safeToolMessage(error, fallback)}`,
    );
    process.exit(1);
  });
}

// static imports initialize this adapter before an entrypoint validates inputs
// or starts work; test runners and imported libraries retain their own boundary.
const entry = process.argv[1] === undefined ? undefined : path.resolve(process.argv[1]);
const entryPolicies: Readonly<Record<string, ToolErrorCode>> = {
  "generate-diagnostic-codes.ts": "tool.input_invalid",
  "generate-config-types.ts": "tool.input_invalid",
  "generate-projectconfig-loader.ts": "tool.unexpected",
  "generate-publisher-model.ts": "tool.input_invalid",
  "build-feedback-toolbar.ts": "tool.unexpected",
  "clean-package.ts": "tool.unexpected",
  "verify-tnl-install.ts": "tool.validation_failed",
  "verify-packages.ts": "tool.validation_failed",
  "release-version.ts": "tool.input_invalid",
  "publish-tnl-packages.ts": "tool.process_failed",
  "update-homebrew.ts": "tool.input_invalid",
  "render-local-capacity.ts": "tool.validation_failed",
  "pack-tnl.ts": "tool.validation_failed",
  "normalize-openapi-go.ts": "tool.input_invalid",
  "run-go-tests-with-postgres.ts": "tool.process_failed",
  "release-check.ts": "tool.validation_failed",
  "runtime-load.ts": "tool.process_failed",
};
if (entry !== undefined && path.dirname(entry) === import.meta.dirname) {
  const policy = entryPolicies[path.basename(entry)];
  if (policy !== undefined) installToolFailureHandler({ url: pathToFileURL(entry).href }, policy);
}
