export type TnlErrorCode =
  | "sdk.publication_failed"
  | "sdk.owner_conflict"
  | "sdk.registration_stale"
  | "sdk.authentication_required"
  | "sdk.publisher_setup_required"
  | "sdk.publisher_credential_file_invalid"
  | "sdk.configuration_invalid"
  | "sdk.service_unprepared"
  | "sdk.connection_unavailable"
  | "sdk.connection_unprepared"
  | "sdk.connection_server_only"
  | "sdk.workload_required"
  | "sdk.workload_manifest_invalid"
  | "sdk.workload_assertion_unavailable"
  | "sdk.workload_denied"
  | "sdk.workload_unavailable"
  | "sdk.workload_response_invalid"
  | "sdk.runtime_invalid"
  | "sdk.protocol_unsupported"
  | "sdk.project_unavailable"
  | "sdk.target_invalid"
  | "sdk.dev_unavailable"
  | "sdk.response_invalid"
  | "sdk.request_rejected"
  | "sdk.listener_failed"
  | "sdk.cleanup_failed"
  | "sdk.native_unsupported"
  | "sdk.native_missing"
  | "sdk.native_invalid"
  | "sdk.process_unavailable"
  | "sdk.unexpected";

type FailureClass = "invalid" | "internal" | "unavailable" | "conflict";
type Retry = "never" | "later" | "after_change";
const definitions: Record<TnlErrorCode, { class: FailureClass; retry: Retry; message: string }> = {
  "sdk.publication_failed": {
    class: "unavailable",
    retry: "later",
    message:
      "the ad-hoc public URL did not become available; check tnl status and the local listener",
  },
  "sdk.owner_conflict": {
    class: "conflict",
    retry: "after_change",
    message: "another live app owns this service; stop it before starting another",
  },
  "sdk.registration_stale": {
    class: "conflict",
    retry: "later",
    message: "app registration expired; prepare and register its listener again",
  },
  "sdk.authentication_required": {
    class: "unavailable",
    retry: "after_change",
    message: "tnl needs a saved login; run tnl auth login, then start the app again",
  },
  "sdk.publisher_setup_required": {
    class: "invalid",
    retry: "after_change",
    message:
      "no namespace publisher is set up; run tnl publisher setup --namespace, then try again",
  },
  "sdk.publisher_credential_file_invalid": {
    class: "invalid",
    retry: "after_change",
    message: "the selected publisher file is invalid; check the file and its permissions",
  },
  "sdk.configuration_invalid": {
    class: "invalid",
    retry: "after_change",
    message:
      "tnl framework configuration is invalid; check the integration options and project configuration",
  },
  "sdk.service_unprepared": {
    class: "unavailable",
    retry: "after_change",
    message:
      "tnl service metadata is unavailable; start the app with its tnl integration before reading tnl.services",
  },
  "sdk.connection_unavailable": {
    class: "unavailable",
    retry: "later",
    message: "the native connection owner is unavailable; prepare connections again",
  },
  "sdk.connection_unprepared": {
    class: "unavailable",
    retry: "after_change",
    message:
      "connection settings are not prepared; await tnl.connect first or set TNL_CONNECTION_HANDLE to a prepared native handle",
  },
  "sdk.connection_server_only": {
    class: "unavailable",
    retry: "after_change",
    message: "native connections require Node.js or Bun; call tnl.connect from server code",
  },
  "sdk.workload_required": {
    class: "invalid",
    retry: "after_change",
    message:
      "select one saved workload with TNL_WORKLOAD or configureWorkload before calling tnl.connect",
  },
  "sdk.workload_manifest_invalid": {
    class: "invalid",
    retry: "after_change",
    message:
      "the workload manifest is missing or invalid; package .tnl/generated/workloads.json from tnl generate with the server artifact",
  },
  "sdk.workload_assertion_unavailable": {
    class: "unavailable",
    retry: "after_change",
    message:
      "the selected workload assertion is unavailable; check its request-scoped provider or configured token source",
  },
  "sdk.workload_denied": {
    class: "conflict",
    retry: "after_change",
    message: "workload access was denied; check the saved workload policy and service access",
  },
  "sdk.workload_unavailable": {
    class: "unavailable",
    retry: "later",
    message:
      "workload request preparation failed; check control availability before trying a new request",
  },
  "sdk.workload_response_invalid": {
    class: "internal",
    retry: "after_change",
    message: "control returned an invalid workload response; check server and SDK compatibility",
  },
  "sdk.runtime_invalid": {
    class: "invalid",
    retry: "after_change",
    message: "tnl project metadata is invalid; restart the app to prepare it again",
  },
  "sdk.protocol_unsupported": {
    class: "invalid",
    retry: "after_change",
    message: "unsupported local publisher protocol; upgrade tnl and its framework integrations",
  },
  "sdk.project_unavailable": {
    class: "unavailable",
    retry: "after_change",
    message: "tnl project metadata is unavailable; check file access and restart the app",
  },
  "sdk.target_invalid": {
    class: "invalid",
    retry: "after_change",
    message:
      "tnl development target must be an HTTP or HTTPS listener on a port between 1 and 65535",
  },
  "sdk.dev_unavailable": {
    class: "unavailable",
    retry: "later",
    message: "the local tnl publisher is unavailable; restart the app to reconnect",
  },
  "sdk.response_invalid": {
    class: "internal",
    retry: "after_change",
    message:
      "the local publisher returned an invalid response; upgrade tnl and its integrations and restart the app",
  },
  "sdk.request_rejected": {
    class: "conflict",
    retry: "after_change",
    message: "the local publisher rejected the framework request; check tnl status",
  },
  "sdk.listener_failed": {
    class: "unavailable",
    retry: "after_change",
    message: "the development listener could not start; check the listener and restart the app",
  },
  "sdk.cleanup_failed": {
    class: "internal",
    retry: "after_change",
    message:
      "development listener setup and cleanup failed; stop the local service before retrying",
  },
  "sdk.native_unsupported": {
    class: "invalid",
    retry: "never",
    message: "unsupported platform; tnl supports macOS and Linux on arm64 and x64",
  },
  "sdk.native_missing": {
    class: "invalid",
    retry: "after_change",
    message:
      "the native tnl package is missing; reinstall @tnldotdev/tnl without disabling optional dependencies",
  },
  "sdk.native_invalid": {
    class: "invalid",
    retry: "after_change",
    message:
      "the native tnl package is invalid or does not match the launcher; reinstall @tnldotdev/tnl",
  },
  "sdk.process_unavailable": {
    class: "unavailable",
    retry: "after_change",
    message:
      "the tnl launcher could not start the native process; check Node.js support and the installed package",
  },
  "sdk.unexpected": {
    class: "internal",
    retry: "never",
    message:
      "the tnl integration failed unexpectedly; restart the local service and report the failure if it continues",
  },
};

export class TnlError extends Error {
  readonly code: TnlErrorCode;
  readonly class: FailureClass;
  readonly retry: Retry;
  constructor(code: TnlErrorCode, options?: ErrorOptions) {
    super(definitions[code].message, options);
    this.name = "TnlError";
    this.code = code;
    this.class = definitions[code].class;
    this.retry = definitions[code].retry;
  }
}

// private causes can contain assertions, headers, or response bodies. retain
// their identity without exposing them through Error.cause, inspection, or JSON.
const privateCauses = new WeakMap<TnlError, unknown>();
export function privateTnlError(code: TnlErrorCode, cause: unknown): TnlError {
  const error = new TnlError(code);
  privateCauses.set(error, cause);
  return error;
}

export class TnlCleanupError extends TnlError {
  readonly errors: readonly unknown[];
  constructor(error: unknown, cleanupError: unknown) {
    super("sdk.cleanup_failed", { cause: error });
    this.errors = [error, cleanupError];
  }
}

export function classifyTnlError(error: unknown, code: TnlErrorCode): TnlError {
  return error instanceof TnlError ? error : new TnlError(code, { cause: error });
}

export function safeTnlMessage(error: unknown): string {
  return definitions[error instanceof TnlError ? error.code : "sdk.unexpected"].message;
}
