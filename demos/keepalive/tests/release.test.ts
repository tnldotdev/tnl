import { expect, it } from "vitest";
import { WASM_PATH, WORKER_PATH, digest, parseRelease } from "../src/release.ts";

it("rejects a legacy font asset even when the release digest matches", async () => {
  const encoder = new TextEncoder();
  const bytes = encoder.encode("fixture");
  const content = { size: bytes.byteLength, sha256: await digest(bytes) };
  const assets = ["/index.html", WORKER_PATH, WASM_PATH].map((path) => ({ path, ...content }));
  const manifest = async (entries: typeof assets) => ({
    id: await digest(encoder.encode(JSON.stringify(entries))),
    assets: entries,
  });

  await expect(parseRelease(await manifest(assets))).resolves.toMatchObject({ assets });
  await expect(
    parseRelease(
      await manifest([...assets, { path: "/jetbrains-mono-latin-wght-normal.woff2", ...content }]),
    ),
  ).rejects.toMatchObject({ issues: [{ path: ["assets", 3, "path"] }] });
});
