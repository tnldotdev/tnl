import { spawn } from "node:child_process";
import { ActionError, checkCancelled, ownedError } from "./errors.ts";

const maxBytes = 128 * 1024;

// never forward child output: even errors from a broken executable may echo stdin.
async function captureCommand(
  executable: string,
  args: string[],
  options: { cwd: string; timeout: number; input?: string; signal?: AbortSignal },
): Promise<{ output: string; failure: ActionError | undefined }> {
  if (Buffer.byteLength(options.input ?? "") > maxBytes) {
    throw new ActionError("TNL_ACTION_REQUEST_TOO_LARGE");
  }
  checkCancelled(options.signal);
  return await new Promise((resolve, reject) => {
    const env = { ...process.env };
    delete env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
    delete env.ACTIONS_ID_TOKEN_REQUEST_URL;
    // RUNNER_TRACKING_ID deliberately remains inherited.
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(executable, args, { cwd: options.cwd, env, stdio: "pipe" });
    } catch (cause) {
      reject(new ActionError("TNL_ACTION_EXEC_FAILED", { cause }));
      return;
    }
    const output: Buffer[] = [];
    let bytes = 0;
    let failure: ActionError | undefined;
    let force: NodeJS.Timeout | undefined;
    const stop = (error: ActionError) => {
      if (failure !== undefined) return;
      failure = error;
      child.kill("SIGTERM");
      // the native start command gets time to join its own partial startup.
      force = setTimeout(() => child.kill("SIGKILL"), 25_000);
    };
    const abort = () =>
      stop(new ActionError("TNL_ACTION_CANCELLED", { cause: options.signal?.reason }));
    const timer = setTimeout(
      () => stop(new ActionError("TNL_ACTION_COMMAND_TIMEOUT")),
      options.timeout,
    );
    options.signal?.addEventListener("abort", abort, { once: true });
    const finish = () => {
      clearTimeout(timer);
      clearTimeout(force);
      options.signal?.removeEventListener("abort", abort);
    };
    child.on("error", (cause) => {
      failure ??= new ActionError("TNL_ACTION_EXEC_FAILED", { cause });
    });
    child.stdout?.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > maxBytes) stop(new ActionError("TNL_ACTION_RESPONSE_TOO_LARGE"));
      else output.push(chunk);
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > maxBytes) stop(new ActionError("TNL_ACTION_RESPONSE_TOO_LARGE"));
    });
    child.stdin?.on("error", () => {});
    child.on("close", (code, signal) => {
      finish();
      // preserve a raced cancellation/timeout even if the child exits cleanly.
      // connectorJSON observes any complete response before reporting the failure.
      if (code !== 0)
        failure ??= new ActionError("TNL_ACTION_COMMAND_FAILED", { cause: { code, signal } });
      resolve({ output: Buffer.concat(output).toString("utf8"), failure });
    });
    child.stdin?.end(options.input ?? "");
    if (options.signal?.aborted) abort();
  });
}

export async function command(
  executable: string,
  args: string[],
  options: Parameters<typeof captureCommand>[2],
): Promise<string> {
  try {
    const result = await captureCommand(executable, args, options);
    if (result.failure) throw result.failure;
    return result.output;
  } catch (cause) {
    throw ownedError(cause, "TNL_ACTION_EXEC_FAILED");
  }
}

export async function connectorJSON(
  executable: string,
  args: string[],
  options: Parameters<typeof command>[2] & { onResponse?: (value: unknown) => Promise<void> },
): Promise<unknown> {
  const result = await captureCommand(
    executable,
    ["--no-telemetry", "runtime", "connections", ...args],
    options,
  ).catch((cause: unknown) => {
    throw ownedError(cause, "TNL_ACTION_EXEC_FAILED");
  });
  let value: unknown;
  try {
    value = JSON.parse(result.output) as unknown;
  } catch (cause) {
    if (result.failure) throw result.failure;
    throw new ActionError("TNL_ACTION_JSON_INVALID", { cause });
  }
  // a complete response may carry the only cleanup capability even when the
  // starter exits unsuccessfully. retain it without treating startup as success.
  try {
    await options.onResponse?.(value);
  } catch (cause) {
    if (result.failure)
      throw new ActionError(result.failure.code, {
        cause: new AggregateError([result.failure, cause]),
      });
    throw ownedError(cause, "TNL_ACTION_STATE_FAILED");
  }
  if (result.failure) throw result.failure;
  return value;
}
