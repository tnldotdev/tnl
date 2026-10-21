// only this catalog supplies text at the Actions output boundary. causes may
// contain credentials, filesystem paths, provider responses, or invalid input.
const messages = {
  TNL_ACTION_SETUP_FAILED: "tnl action setup failed",
  TNL_ACTION_PLATFORM_UNSUPPORTED: "tnl connect currently supports Linux GitHub-hosted jobs",
  TNL_ACTION_WORKLOAD_INVALID: "workload must be a project workload key",
  TNL_ACTION_TIMEOUT_INVALID: "timeout must be 1-300 seconds",
  TNL_ACTION_SERVICES_INVALID: "services must contain distinct newline-separated service keys",
  TNL_ACTION_DIRECTORY_INVALID: "could not resolve the project directory; check working-directory",
  TNL_ACTION_TEMP_INVALID:
    "RUNNER_TEMP must be an absolute runner-owned directory outside the project checkout",
  TNL_ACTION_SESSION_FAILED: "could not prepare the private tnl action session",
  TNL_ACTION_STATE_FAILED: "could not save the private tnl cleanup state",
  TNL_ACTION_STATE_INVALID: "invalid saved tnl action state",
  TNL_ACTION_CLEANUP_PATH_INVALID: "invalid saved tnl cleanup paths",
  TNL_ACTION_CLEANUP_FAILED:
    "tnl connection cleanup failed; the saved native handle could not confirm joined cleanup",
  TNL_ACTION_CLEANUP_UNCONFIRMED:
    "tnl startup delivered no cleanup handle; any surviving native owner remains bounded by its fixed deadline and runner cleanup",
  TNL_ACTION_CANCELLED: "tnl connection startup was cancelled",
  TNL_ACTION_BINARY_SELECTION_INVALID: "select either version or cli-path",
  TNL_ACTION_VERSION_INVALID:
    "version must be an exact release version, without a v prefix or range",
  TNL_ACTION_BINARY_UNAVAILABLE:
    "could not resolve the installed exact @tnldotdev/tnl platform binary; install locked dependencies including optional packages, or select version or cli-path explicitly",
  TNL_ACTION_BINARY_COPY_FAILED:
    "could not copy the selected native executable; check cli-path and runner temp permissions",
  TNL_ACTION_LEGAL_FILES_MISSING:
    "the installed tnl platform package is missing required legal files",
  TNL_ACTION_INSTALL_FAILED:
    "could not install the selected exact tnl release; check npm access and the selected version",
  TNL_ACTION_REQUEST_TOO_LARGE: "tnl startup request exceeds the native limit",
  TNL_ACTION_EXEC_FAILED: "could not execute the selected tnl binary",
  TNL_ACTION_COMMAND_FAILED:
    "tnl native command failed; check the selected binary, applied binding, and saved workload policy",
  TNL_ACTION_COMMAND_TIMEOUT: "tnl native command timed out",
  TNL_ACTION_RESPONSE_TOO_LARGE: "tnl native response exceeds the limit",
  TNL_ACTION_JSON_INVALID:
    "tnl returned invalid machine JSON; use a release with connection schema 1",
  TNL_ACTION_CAPABILITIES_INVALID:
    "the selected tnl binary lacks connection schema 1 capabilities; select a compatible exact release",
  TNL_ACTION_CONTEXT_INVALID: "tnl returned an invalid or mismatched workload context",
  TNL_ACTION_OIDC_FAILED: "could not obtain GitHub OIDC proof; grant this job id-token: write",
  TNL_ACTION_READY_INVALID: "tnl did not return valid ready connections",
  TNL_ACTION_EXPORT_FAILED: "could not export the prepared tnl connections to the job environment",
} as const;

export type ActionErrorCode = keyof typeof messages;

export class ActionError extends Error {
  readonly code: ActionErrorCode;

  constructor(code: ActionErrorCode, options?: ErrorOptions) {
    super(messages[code], options);
    this.name = "ActionError";
    this.code = code;
  }
}

export function ownedError(error: unknown, fallback: ActionErrorCode): ActionError {
  return error instanceof ActionError ? error : new ActionError(fallback, { cause: error });
}

export function safeActionMessage(error: unknown, fallback: ActionErrorCode): string {
  const code = error instanceof ActionError ? error.code : fallback;
  return `[${code}] ${messages[code]}`;
}

export function checkCancelled(signal?: AbortSignal): void {
  if (signal?.aborted) throw new ActionError("TNL_ACTION_CANCELLED", { cause: signal.reason });
}
