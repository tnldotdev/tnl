import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, onTestFinished, test } from "vitest";
import { startTestBootstrap, waitForBootstrapRequest } from "./test-helper/bootstrap.js";
import { startTestProcess } from "./test-helper/process.js";
import { temporaryDirectory } from "./test-helper/project.js";

const entrypoint = fileURLToPath(new URL("./fixtures/bun/server.ts", import.meta.url));

test(
  "two Bun Hono servers register different ports and read project URLs during import",
  { timeout: 30_000 },
  async () => {
    const a = await startTestBootstrap();
    const b = await startTestBootstrap();
    const project = (label: string) =>
      JSON.stringify({
        namespace: `${label}.example`,
        dev: true,
        services: {
          web: {
            hostname: `web.${label}.example`,
            namespace: `${label}.example`,
            url: `https://web.${label}.example`,
          },
        },
      });
    const first = startTestProcess(
      "bun",
      [entrypoint],
      {
        cwd: await temporaryDirectory("tnl-bun-first-"),
        env: { ...a.environment, NODE_ENV: "development" },
      },
      project("first"),
    );
    const second = startTestProcess(
      "bun",
      [entrypoint],
      {
        cwd: await temporaryDirectory("tnl-bun-second-"),
        env: { ...b.environment, NODE_ENV: "development" },
      },
      project("second"),
    );
    await Promise.all([first.ready(), second.ready()]);
    const [firstTarget, secondTarget] = await Promise.all([
      waitForBootstrapRequest(a, 1, 20_000, first.assertRunning),
      waitForBootstrapRequest(b, 1, 20_000, second.assertRunning),
    ]);
    expect(a.requests[0]?.body).toEqual({ protocol: 1, framework: "bun" });
    expect(firstTarget.body).toMatchObject({ protocol: 1, framework: "bun" });
    const firstURL = (firstTarget.body as { target: string }).target;
    const secondURL = (secondTarget.body as { target: string }).target;
    expect(firstURL).toMatch(/^http:\/\/127\.0\.0\.1:[1-9][0-9]*$/);
    expect(secondURL).not.toBe(firstURL);
    const responses = await Promise.all([fetch(firstURL), fetch(secondURL)]);
    for (const [index, response] of responses.entries()) {
      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toEqual({
        siblingURL: `https://web.${index === 0 ? "first" : "second"}.example`,
      });
    }
  },
);

test("Bun hot reload keeps the registered listener available", { timeout: 30_000 }, async () => {
  const directory = await mkdtemp(join(dirname(entrypoint), ".tnl-bun-hot-"));
  onTestFinished(() => rm(directory, { recursive: true, force: true }));
  const source = await readFile(entrypoint, "utf8");
  const hotEntrypoint = join(directory, "server.ts");
  await writeFile(hotEntrypoint, source);
  const bootstrap = await startTestBootstrap();
  const process_ = startTestProcess("bun", ["--hot", hotEntrypoint], {
    env: { ...bootstrap.environment, NODE_ENV: "development" },
  });
  await process_.ready();
  const registered = await waitForBootstrapRequest(bootstrap, 1, 20_000, process_.assertRunning);
  const target = (registered.body as { target: string }).target;
  expect((await fetch(target)).status).toBe(200);
  await writeFile(
    hotEntrypoint,
    source.replace("context.json({ siblingURL })", "context.json({ siblingURL, updated: true })"),
  );
  await expect
    .poll(
      async () => {
        process_.assertRunning();
        const response = await fetch(target);
        return response.json();
      },
      { timeout: 15_000, interval: 100 },
    )
    .toEqual({ updated: true });
  expect(
    bootstrap.requests
      .filter((request) => request.path === "/v1/target")
      .every((request) => (request.body as { target: string }).target === target),
  ).toBe(true);
});
