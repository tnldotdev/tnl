import { cp, mkdtemp, rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { onTestFinished } from "vitest";
import { startTestBootstrap, waitForBootstrapRequest } from "./bootstrap.js";
import { errorMessage, startTestProcess, type TestProcess } from "./process.js";

export async function startFrameworkFixture(
  framework: "next" | "vite",
  arguments_: readonly string[] = [],
  environment: Readonly<Record<string, string | undefined>> = {},
) {
  // stay beneath the package: Node and Turbopack resolve the installed matrix version,
  // React, and tnl's real package exports through the same ancestors as the source fixture.
  const base = new URL(`../fixtures/${framework}/`, import.meta.url);
  const directory = await mkdtemp(fileURLToPath(new URL("workspace-", base)));
  let process_: TestProcess | undefined;
  let closing: Promise<void> | undefined;
  const close = () =>
    (closing ??= (async () => {
      await process_?.close();
      await rm(directory, { force: true, recursive: true });
    })());
  onTestFinished(close);
  try {
    await cp(new URL("app/", base), directory, {
      recursive: true,
      filter: (source) =>
        !/(?:^|[/\\])(?:\.next|node_modules|next-env\.d\.ts|tsconfig\.json)(?:[/\\]|$)/.test(
          source,
        ),
    });
    const bootstrap = await startTestBootstrap();
    const cli = fileURLToPath(
      new URL(
        framework === "next"
          ? "../node_modules/next/dist/bin/next"
          : "../node_modules/vite/bin/vite.js",
        import.meta.url,
      ),
    );
    const running = startTestProcess(process.execPath, [cli, ...arguments_], {
      cwd: directory,
      env: { NODE_ENV: "development", ...bootstrap.environment, ...environment },
    });
    process_ = running;
    await running.ready();
    return {
      directory,
      close,
      output: running.output,
      request: (index = 0) =>
        waitForBootstrapRequest(bootstrap, index, 30_000, running.assertRunning),
      async diagnose<T>(callback: () => Promise<T>): Promise<T> {
        try {
          return await callback();
        } catch (error) {
          throw new Error(`${errorMessage(error)}\n${running.output()}`, { cause: error });
        }
      },
    };
  } catch (error) {
    await close();
    throw error;
  }
}
