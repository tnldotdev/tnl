import { mkdtemp, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { expect, it } from "vitest";
import * as z from "zod/mini";
import { siteRelease } from "../scripts/release.ts";
import { startPage } from "../scripts/page.ts";
import { hostWordsEsbuild } from "../scripts/host-words.ts";
import { first, second } from "../src/peers/host-words.ts";
import { hostNameSchema } from "../src/peers/host-names.ts";
import { fleets } from "../src/fleets.ts";
import { verifyAsset, WORKER_PATH, WASM_PATH } from "../src/release.ts";
import { pageBundle } from "./page-bundle.ts";

it("pins all built chunks and public files, but never the bootstrap document", async () => {
  const directory = await mkdtemp(join(tmpdir(), "keepalive-release-"));
  try {
    const { files, chunks } = await pageBundle();
    files.set(WORKER_PATH, Buffer.from("fixture worker"));
    files.set(WASM_PATH, Buffer.from("fixture wasm"));
    files.set("/favicon.svg", Buffer.from("<svg></svg>"));
    files.set("/start.html", Buffer.from("bootstrap only"));
    for (const [path, bytes] of files) {
      const target = join(directory, path);
      await mkdir(join(target, ".."), { recursive: true });
      await writeFile(target, bytes);
    }
    const release = await siteRelease(directory);
    expect(release.assets.map(({ path }) => path)).toEqual(
      [...files.keys()].filter((path) => path !== "/start.html").sort(),
    );
    expect(await siteRelease(directory)).toEqual(release);
    for (const chunk of chunks) {
      const asset = release.assets.find(({ path }) => path === `/${chunk.fileName}`);
      if (asset === undefined) throw new Error(`Unpinned chunk: ${chunk.fileName}`);
      const bytes = await readFile(join(directory, chunk.fileName));
      await expect(verifyAsset(asset, bytes)).resolves.toBe(bytes);
      await expect(verifyAsset(asset, new Uint8Array(bytes.length).fill(1))).rejects.toThrow(
        "does not match",
      );
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

it.each(["prod", "ramp"] as const)(
  "keeps the %s bootstrap text and hostname in static HTML",
  async (fleet) => {
    const html = await readFile(new URL("../src/page/index.html", import.meta.url), "utf8");
    const start = startPage(html, fleets[fleet].site);
    expect(start).toContain('id="app" data-start');
    expect(start).toContain("<h1>start keepalive</h1>");
    expect(start).toContain(`href="https://${fleets[fleet].site}"`);
    expect(start).toContain("up to one hour");
    expect(start).not.toContain("This site is served from people's browsers.");
  },
);

it("packs exactly the existing word lists and retains saved-name validation", async () => {
  const result = await build({
    entryPoints: [new URL("../src/peers/host-words.ts", import.meta.url).pathname],
    bundle: true,
    format: "esm",
    write: false,
    plugins: [hostWordsEsbuild],
  });
  const output = result.outputFiles[0]?.text;
  if (output === undefined) throw new Error("Missing packed words.");
  const words = z
    .object({ first: z.array(z.string()), second: z.array(z.string()) })
    .parse(await import(`data:text/javascript;base64,${Buffer.from(output).toString("base64")}`));
  expect(words).toEqual({ first, second });
  for (const word of words.first)
    expect(hostNameSchema.safeParse(`${word}-pine`).success).toBe(true);
  for (const word of words.second)
    expect(hostNameSchema.safeParse(`quiet-${word}`).success).toBe(true);
  expect(hostNameSchema.safeParse("quiet-pine").success).toBe(true);
  expect(hostNameSchema.safeParse("invalid-unknownword").success).toBe(false);
});
