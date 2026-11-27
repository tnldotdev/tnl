import { gzipSync } from "node:zlib";
import { expect, it } from "vitest";
import { pageBundle } from "./page-bundle.ts";

it("budgets the entire initial graph separately from all optional scripts", async () => {
  const { files, chunks, initial } = await pageBundle();
  const scripts = [...files].filter(([path]) => path.endsWith(".js"));
  const reader = scripts.filter(([path]) => initial.has(path));
  expect(reader.reduce((size, [, bytes]) => size + bytes.length, 0)).toBeLessThan(115_000);
  expect(reader.reduce((size, [, bytes]) => size + gzipSync(bytes).length, 0)).toBeLessThan(35_000);
  expect(scripts.reduce((size, [, bytes]) => size + bytes.length, 0)).toBeLessThan(160_000);
  expect(scripts.reduce((size, [, bytes]) => size + gzipSync(bytes).length, 0)).toBeLessThan(
    58_000,
  );
  const modules = chunks
    .filter((chunk) => initial.has(`/${chunk.fileName}`))
    .flatMap((chunk) => chunk.moduleIds);
  expect(modules.some((id) => id.includes("@tanstack/solid-query/"))).toBe(true);
  expect(modules.some((id) => /(?:react|react-dom|preact)\//.test(id))).toBe(false);
  expect(modules.some((id) => /\/(?:host-words|host-names|hosts|turn)\.tsx?$/.test(id))).toBe(
    false,
  );
  expect(modules.some((id) => id.endsWith("/hosting/tab.ts"))).toBe(false);
  for (const chunk of chunks) {
    expect(chunk.fileName).toMatch(/^(app\.js|chunks\/chunk-[a-f0-9]+\.js)$/);
    expect(files.has(`/${chunk.fileName}`)).toBe(true);
  }
  expect(files.get("/index.html")?.toString()).toContain(
    "This site is served from people's browsers.",
  );
});
