import * as core from "@actions/core";
import { chmod, lstat, mkdtemp, realpath, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import {
  checkCapabilities,
  cleanupSchema,
  inside,
  readySchema,
  type Cleanup,
} from "./contract.js";
import { environmentSelectionSchema } from "../../packages/ts/src/internal/connector/contract.js";
import { identitySourceSelectionSchema } from "../../packages/ts/src/internal/identity/validation.js";
import { nativeAcquisitionSchema } from "../../packages/ts/src/internal/identity/source.js";
import { isDeepStrictEqual } from "node:util";
import { connectorJSON } from "./native.js";
import { selectBinary } from "./resolve.js";
import { ActionError, checkCancelled, ownedError, safeActionMessage } from "./errors.js";

const stateKey = "tnl-cleanup";

export async function cleanup(owned: Cleanup): Promise<void> {
  try {
    // a stale handle is still passed to native stop: only native knows whether
    // the owner joined cleanup successfully. never infer success from a PID.
    if (
      !inside(owned.session, owned.binary) ||
      (owned.handle !== undefined && !inside(owned.session, owned.handle))
    ) {
      throw new ActionError("TNL_ACTION_CLEANUP_PATH_INVALID");
    }
    await privatePath(owned.session, owned.session, true);
    if (owned.handle !== undefined) {
      const stopped = await connectorJSON(owned.binary, ["stop", "--handle", owned.handle], {
        cwd: owned.session,
        timeout: 30_000,
      });
      if (
        !z.object({ schema: z.literal(1), state: z.literal("stopped") }).safeParse(stopped).success
      )
        throw new ActionError("TNL_ACTION_CLEANUP_FAILED");
    } else if (owned.start_attempted) {
      // without a delivered capability there is no exact stop operation. retain
      // native files for the owner's fixed-deadline cleanup and runner tracking.
      throw new ActionError("TNL_ACTION_CLEANUP_UNCONFIRMED");
    }
    await rm(owned.session, { recursive: true, force: true });
  } catch (cause) {
    throw ownedError(cause, "TNL_ACTION_CLEANUP_FAILED");
  }
}

async function privatePath(session: string, file: string, directory = false): Promise<void> {
  try {
    const info = await lstat(file);
    const parent = await lstat(path.dirname(file));
    if (
      (!directory && !inside(session, file)) ||
      (await realpath(file)) !== file ||
      (directory ? !info.isDirectory() : !info.isFile()) ||
      info.uid !== process.getuid?.() ||
      (info.mode & 0o777) !== (directory ? 0o700 : 0o600) ||
      (!directory &&
        (!parent.isDirectory() || parent.uid !== info.uid || (parent.mode & 0o777) !== 0o700))
    )
      throw new ActionError("TNL_ACTION_CLEANUP_PATH_INVALID");
  } catch (cause) {
    throw ownedError(cause, "TNL_ACTION_CLEANUP_PATH_INVALID");
  }
}

export async function post(): Promise<void> {
  const saved = core.getState(stateKey);
  if (!saved) return;
  let owned: Cleanup;
  try {
    owned = cleanupSchema.parse(JSON.parse(saved));
  } catch (cause) {
    throw new ActionError("TNL_ACTION_STATE_INVALID", { cause });
  }
  // main may already have cleaned a failed invocation.
  try {
    await stat(owned.session);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return;
    throw new ActionError("TNL_ACTION_CLEANUP_FAILED", { cause: error });
  }
  await cleanup(owned);
  core.info("tnl connections stopped");
}

export async function main(options: {
  signal: AbortSignal;
}): Promise<void> {
  try {
    await setup(options);
  } catch (cause) {
    throw ownedError(cause, "TNL_ACTION_SETUP_FAILED");
  }
}

async function setup(options: Parameters<typeof main>[0]): Promise<void> {
  checkCancelled(options.signal);
  let selection: z.infer<typeof environmentSelectionSchema>;
  let source: z.infer<typeof identitySourceSelectionSchema>;
  let acquisition: z.infer<typeof nativeAcquisitionSchema>;
  const audience = core.getInput("audience");
  try {
    const environment: unknown = JSON.parse(core.getInput("environment"));
    const services: unknown = JSON.parse(core.getInput("services"));
    selection = environmentSelectionSchema.parse({ environment, services, permission_id: core.getInput("permission-id") });
    source = identitySourceSelectionSchema.parse({ kind: "oidc", machine_id: core.getInput("machine-id") });
    acquisition = nativeAcquisitionSchema.parse({ method: "github-actions", audience });
  } catch (cause) { throw new ActionError("TNL_ACTION_CONTEXT_INVALID", { cause }); }
  const timeout = Number(core.getInput("timeout") || "90");
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > 300)
    throw new ActionError("TNL_ACTION_TIMEOUT_INVALID");
  const services = Object.keys(selection.services);
  let directory: string;
  try {
    directory = await realpath(
      path.resolve(
        process.env.GITHUB_WORKSPACE ?? process.cwd(),
        core.getInput("working-directory") || ".",
      ),
    );
  } catch (cause) {
    throw new ActionError("TNL_ACTION_DIRECTORY_INVALID", { cause });
  }
  const runnerTemp = process.env.RUNNER_TEMP;
  if (!runnerTemp || !path.isAbsolute(runnerTemp)) throw new ActionError("TNL_ACTION_TEMP_INVALID");
  let parent: string;
  let workspace: string;
  try {
    parent = await realpath(runnerTemp);
    workspace = await realpath(process.env.GITHUB_WORKSPACE ?? directory);
  } catch (cause) {
    throw new ActionError("TNL_ACTION_TEMP_INVALID", { cause });
  }
  if (
    parent === directory ||
    inside(directory, parent) ||
    parent === workspace ||
    inside(workspace, parent)
  )
    throw new ActionError("TNL_ACTION_TEMP_INVALID");
  let session: string;
  try {
    session = await mkdtemp(path.join(parent, "tnl-action-"));
  } catch (cause) {
    throw new ActionError("TNL_ACTION_SESSION_FAILED", { cause });
  }
  let owned: Cleanup = { session, binary: path.join(session, "binary/tnl") };
  const save = async () => {
    try {
      await writeFile(path.join(session, "cleanup.json"), JSON.stringify(owned), { mode: 0o600 });
      core.saveState(stateKey, JSON.stringify(owned));
    } catch (cause) {
      throw new ActionError("TNL_ACTION_STATE_FAILED", { cause });
    }
  };
  try {
    try {
      await chmod(session, 0o700);
    } catch (cause) {
      throw new ActionError("TNL_ACTION_SESSION_FAILED", { cause });
    }
    await save();
    const binary = await selectBinary({
      directory,
      session,
      version: core.getInput("version"),
      cliPath: core.getInput("cli-path"),
      signal: options.signal,
    });
    owned = { session, binary };
    await save();
    const commandOptions = { cwd: directory, timeout: 30_000, signal: options.signal };
    checkCapabilities(await connectorJSON(binary, ["capabilities"], commandOptions));
    checkCancelled(options.signal);
    // the action transfers its job-owned runtime source explicitly. ordinary
    // SDK request bearers are not background sources, and child env stays filtered.
    const requestURL = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
    const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
    const githubActionsRefresh =
      requestURL && requestToken
        ? { audience, request_url: requestURL, request_token: requestToken }
        : undefined;
    if (process.env.GITHUB_ACTIONS !== "true" || githubActionsRefresh === undefined) throw new ActionError("TNL_ACTION_OIDC_FAILED");
    owned.start_attempted = true;
    await save();
    const started = await connectorJSON(binary, ["environment-start", "--runner-temp", session], {
      ...commandOptions,
      timeout: timeout * 1000,
      input: JSON.stringify({
        schema: 1,
        selection,
        source,
        acquisition,
        github_actions_refresh: githubActionsRefresh,
      }),
      onResponse: async (value) => {
        // retain a usable cleanup capability before checking readiness, even
        // when the starter dies after delivering a complete response.
        const candidate = z.object({ connection_handle: z.string() }).safeParse(value);
        if (candidate.success && inside(session, candidate.data.connection_handle)) {
          owned.handle = candidate.data.connection_handle;
          await save();
        }
      },
    });
    const ready = readySchema.safeParse(started);
    if (
      !ready.success ||
      ready.data.executable !== binary ||
      owned.handle !== ready.data.connection_handle ||
      !isDeepStrictEqual(ready.data.environment.environment, selection.environment) ||
      Object.keys(ready.data.environment.services).length !== services.length ||
      services.some((key) => ready.data.environment.services[key]?.protocol !== selection.services[key]) ||
      Object.keys(ready.data.project_runtime.services).length !== services.length ||
      services.some((key) => ready.data.project_runtime.services[key]?.protocol !== selection.services[key]) ||
      (ready.data.kubeconfig !== undefined && !inside(session, ready.data.kubeconfig))
    )
      throw new ActionError("TNL_ACTION_READY_INVALID", {
        cause: ready.success ? undefined : ready.error,
      });
    try {
      await privatePath(session, ready.data.connection_handle);
      if (ready.data.kubeconfig !== undefined) await privatePath(session, ready.data.kubeconfig);
    } catch (cause) {
      throw new ActionError("TNL_ACTION_READY_INVALID", { cause });
    }
    checkCancelled(options.signal);
    try {
      core.setSecret(ready.data.connection_handle);
      core.exportVariable("TNL_CONNECTION_HANDLE", ready.data.connection_handle);
      core.exportVariable("TNL_PROJECT_RUNTIME", JSON.stringify(ready.data.project_runtime));
      if (ready.data.kubeconfig !== undefined)
        core.exportVariable("KUBECONFIG", ready.data.kubeconfig);
      core.info("tnl connections ready");
    } catch (cause) {
      throw new ActionError("TNL_ACTION_EXPORT_FAILED", { cause });
    }
  } catch (error) {
    const failure = ownedError(error, "TNL_ACTION_SETUP_FAILED");
    try {
      await cleanup(owned);
    } catch (cause) {
      core.warning(safeActionMessage(cause, "TNL_ACTION_CLEANUP_FAILED"));
      throw new ActionError(failure.code, {
        cause: new AggregateError([failure, cause]),
      });
    }
    throw failure;
  }
}
