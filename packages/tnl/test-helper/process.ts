import { spawn, type ChildProcess, type SpawnOptions } from "node:child_process";
import { onTestFinished } from "vitest";
import { subprocessEnvironment } from "./environment.js";

export interface TestProcess {
  readonly child: ChildProcess;
  ready(): Promise<void>;
  assertRunning(): void;
  close(): Promise<void>;
  output(): string;
}

export function startTestProcess(
  command: string,
  arguments_: readonly string[],
  options: SpawnOptions = {},
  projectRuntime?: string,
): TestProcess {
  const grouped = process.platform !== "win32";
  const environment = subprocessEnvironment(options.env);
  if (projectRuntime !== undefined) environment.TNL_PROJECT_RUNTIME = projectRuntime;
  const child = spawn(command, arguments_, {
    ...options,
    env: environment,
    detached: grouped,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  const collect = (chunk: Buffer | string) => {
    output = `${output}${chunk.toString()}`.slice(-16_384);
  };
  // Drain both pipes immediately, including while startup/termination is being awaited.
  child.stdout?.on("data", collect);
  child.stderr?.on("data", collect);
  let spawnError: Error | undefined;
  const spawned = new Promise<void>((resolve) => {
    child.once("spawn", resolve);
    child.on("error", (error) => {
      spawnError = error;
      resolve();
    });
  });
  const closed = new Promise<void>((resolve) => child.once("close", () => resolve()));
  const signal = (value: NodeJS.Signals) => {
    if (child.pid === undefined) return;
    try {
      if (grouped) process.kill(-child.pid, value);
      else child.kill(value);
    } catch (error) {
      if (!(error instanceof Error && "code" in error && error.code === "ESRCH")) throw error;
    }
  };
  let closing: Promise<void> | undefined;
  const close = () =>
    (closing ??= (async () => {
      signal("SIGTERM");
      if (!(await settlesWithin(closed, 2000))) {
        signal("SIGKILL");
        if (!(await settlesWithin(closed, 2000)))
          throw new Error(`child process did not close after SIGKILL\n${output}`);
      }
      // The framework launcher may have exited before its descendants.
      if (grouped) signal("SIGKILL");
    })());
  onTestFinished(close);
  return {
    child,
    close,
    output: () => output,
    async ready() {
      await spawned;
      if (spawnError !== undefined) throw spawnError;
    },
    assertRunning() {
      if (spawnError !== undefined) throw spawnError;
      if (child.exitCode !== null || child.signalCode !== null)
        throw new Error(`framework exited before registration\n${output}`);
    },
  };
}

async function settlesWithin(promise: Promise<void>, timeout: number): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise.then(() => true),
      new Promise<false>((resolve) => {
        timer = setTimeout(() => resolve(false), timeout);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
