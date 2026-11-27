import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { digest, parseRelease, type Asset } from "../src/release.ts";

export async function siteRelease(directory: string) {
  async function paths(relative: string): Promise<string[]> {
    const entries = await readdir(path.join(directory, relative), { withFileTypes: true });
    return (
      await Promise.all(
        entries.map((entry) => {
          const name = path.posix.join(relative, entry.name);
          if (entry.isDirectory()) return paths(name);
          if (!entry.isFile()) throw new Error(`Unexpected release entry: ${name}`);
          // the bootstrap document is served only by the separate start hostname.
          return name === "start.html" ? [] : [name];
        }),
      )
    ).flat();
  }
  const assets: Asset[] = await Promise.all(
    (await paths("")).sort().map(async (name) => {
      const bytes = await readFile(path.join(directory, name));
      return { path: `/${name}`, size: bytes.byteLength, sha256: await digest(bytes) };
    }),
  );
  return parseRelease({
    id: await digest(new TextEncoder().encode(JSON.stringify(assets))),
    assets,
  });
}
