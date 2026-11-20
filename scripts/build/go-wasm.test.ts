import { chmod, mkdtemp, readdir, readFile, rm, watch, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildGoWasm } from "./go-wasm.ts";

describe.skipIf(process.platform === "win32")("Go/WASM build", () => {
  let directory: string;
  let output: string;
  beforeEach(async () => {
    directory = await mkdtemp(path.join(tmpdir(), "tnl-go-wasm-test-"));
    output = path.join(directory, "module.wasm");
    vi.stubEnv("PATH", `${directory}${path.delimiter}${process.env.PATH}`);
    await writeFile(output, "previous artifact");
    await tool(
      "go",
      `[ "$GOOS/$GOARCH/$CGO_ENABLED" = js/wasm/0 ] &&
       [ "$2" = '-tags=fixture' ] && printf 'unoptimized' > "$6"`,
    );
  });

  afterEach(async () => {
    await rm(directory, { recursive: true, force: true });
  });

  async function tool(name: string, source: string) {
    const file = path.join(directory, name);
    await writeFile(file, `#!/bin/sh\n${source}\n`);
    await chmod(file, 0o755);
  }

  it("installs the optimized artifact and removes temporary files", async () => {
    await tool("wasm-opt", `test "$(cat "$1")" = unoptimized && printf 'optimized' > "$6"`);
    await buildGoWasm({ cwd: directory, tags: "fixture", output });
    expect(await readFile(output, "utf8")).toBe("optimized");
    expect((await readdir(directory)).sort()).toEqual(["go", "module.wasm", "wasm-opt"]);
  });

  it("keeps the previous artifact if optimization fails after writing", async () => {
    await tool("wasm-opt", `printf 'partial' > "$6"\nexit 2`);
    await expect(buildGoWasm({ cwd: directory, tags: "fixture", output })).rejects.toMatchObject({
      code: 2,
    });
    expect(await readFile(output, "utf8")).toBe("previous artifact");
    expect((await readdir(directory)).sort()).toEqual(["go", "module.wasm", "wasm-opt"]);
  });

  it("waits for the aborted optimizer to exit before removing temporary files", async () => {
    // the optimizer writes once more on SIGTERM. cleanup must happen after that write.
    await tool(
      "wasm-opt",
      `trap 'printf "partial" > "$6" && printf "stopped" > stopped; exit 0' TERM
       printf 'ready' > ready
       while :; do :; done`,
    );
    const watcher = watch(directory, { signal: AbortSignal.timeout(5_000) });
    const pending = watcher.next();
    const lifetime = new AbortController();
    const build = buildGoWasm({ cwd: directory, tags: "fixture", output, signal: lifetime.signal });
    const aborted = expect(build).rejects.toMatchObject({ name: "AbortError" });
    try {
      let event = await pending;
      while (!event.done && event.value.filename !== "ready") event = await watcher.next();
      expect(event.done).toBe(false);
    } finally {
      lifetime.abort();
      await watcher.return?.();
      await aborted;
    }
    expect(await readFile(path.join(directory, "stopped"), "utf8")).toBe("stopped");
    expect(await readFile(output, "utf8")).toBe("previous artifact");
    expect((await readdir(directory)).sort()).toEqual([
      "go",
      "module.wasm",
      "ready",
      "stopped",
      "wasm-opt",
    ]);
  });
});
