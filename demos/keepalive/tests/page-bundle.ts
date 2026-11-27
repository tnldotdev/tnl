import { fileURLToPath } from "node:url";
import { build } from "vite";

export async function pageBundle() {
  const result = await build({
    configFile: fileURLToPath(new URL("../vite.config.ts", import.meta.url)),
    define: { KEEPALIVE_FLEET: JSON.stringify("prod") },
    build: { write: false },
    logLevel: "silent",
  });
  if (Array.isArray(result) || !("output" in result)) throw new Error("Expected one page build.");
  const files = new Map(
    result.output.map((file) => [
      `/${file.fileName}`,
      Buffer.from(file.type === "chunk" ? file.code : file.source),
    ]),
  );
  const chunks = result.output.filter((file) => file.type === "chunk");
  const initial = new Set<string>();
  function visit(name: string) {
    if (initial.has(`/${name}`)) return;
    const chunk = chunks.find((file) => file.fileName === name);
    if (chunk === undefined) throw new Error(`Missing chunk: ${name}`);
    initial.add(`/${name}`);
    for (const dependency of chunk.imports) visit(dependency);
  }
  visit("app.js");
  return { files, chunks, initial };
}
