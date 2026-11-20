import { execFile, type ExecFileOptions } from "node:child_process";
import { mkdtemp, rename, rm } from "node:fs/promises";
import path from "node:path";

export const sdkWasmPackage = "./packages/ts/wasm";
export const goWasmEnv = { GOOS: "js", GOARCH: "wasm", CGO_ENABLED: "0" };

export async function buildGoWasm({
  cwd,
  tags,
  output,
  signal,
}: {
  cwd: string;
  tags: string;
  output: string;
  signal?: AbortSignal;
}): Promise<void> {
  signal?.throwIfAborted();
  const directory = await mkdtemp(path.join(path.dirname(output), ".go-wasm-"));
  const unoptimized = path.join(directory, "unoptimized.wasm");
  const optimized = path.join(directory, "optimized.wasm");
  const options = { cwd, signal, maxBuffer: 4 << 20 };
  try {
    await run(
      "go",
      ["build", `-tags=${tags}`, "-trimpath", "-ldflags=-s -w", "-o", unoptimized, sdkWasmPackage],
      { ...options, env: { ...process.env, ...goWasmEnv } },
    );
    await run(
      "wasm-opt",
      [
        unoptimized,
        "-Oz",
        "--enable-bulk-memory",
        "--enable-nontrapping-float-to-int",
        "-o",
        optimized,
      ],
      options,
    );
    signal?.throwIfAborted();
    await rename(optimized, output);
  } catch (error) {
    try {
      await rm(directory, { recursive: true, force: true });
    } catch (cleanupError) {
      throw new AggregateError([error, cleanupError], "WASM build and cleanup failed");
    }
    throw error;
  }
  await rm(directory, { recursive: true, force: true });
}

function run(file: string, args: string[], options: ExecFileOptions): Promise<void> {
  return new Promise((resolve, reject) => {
    let failure: Error | null = null;
    const child = execFile(file, args, options, (error) => {
      failure = error;
    });
    // abort can invoke the callback before the child stops writing files.
    child.once("close", () => (failure === null ? resolve() : reject(failure)));
  });
}
