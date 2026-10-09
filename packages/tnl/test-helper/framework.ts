import { chmod, cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { onTestFinished } from "vitest";
import { startTestBootstrap, waitForBootstrapRequest, type TestBootstrap } from "./bootstrap.js";
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
    await installRuntimeFixture(directory, bootstrap);
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

export async function installRuntimeFixture(
  directory: string,
  bootstrap: TestBootstrap,
): Promise<void> {
  await writeFile(
    join(directory, "package.json"),
    JSON.stringify({ name: "tnl-framework-fixture", type: "module" }),
  );
  // mock only native process discovery in this isolated package copy. framework
  // startup, bound listener reporting, metadata, HTTP, and HMR remain real.
  const packageDirectory = join(directory, "node_modules", "@tnldotdev", "tnl");
  await mkdir(packageDirectory, { recursive: true });
  await cp(new URL("../dist/", import.meta.url), join(packageDirectory, "dist"), {
    recursive: true,
  });
  await cp(new URL("../package.json", import.meta.url), join(packageDirectory, "package.json"));
  const binary = join(directory, "native-publisher");
  await writeFile(
    binary,
    `#!${process.execPath}\nprocess.stdout.write(${JSON.stringify(JSON.stringify({ protocol: 1, socket: bootstrap.socket }))});\n`,
  );
  await chmod(binary, 0o700);
  await writeFile(
    join(packageDirectory, "dist", "internal", "launcher.js"),
    `export function resolveNativeBinary() { return ${JSON.stringify(binary)}; }\n`,
  );
}
