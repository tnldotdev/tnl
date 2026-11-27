import { fileURLToPath } from "node:url";
import type { Plugin as EsbuildPlugin } from "esbuild";
import type { Plugin as VitePlugin } from "vite";
import { first, second } from "../src/peers/host-words.ts";

const source = fileURLToPath(new URL("../src/peers/host-words.ts", import.meta.url));
// keep the exact accepted vocabulary; omit unused words and JSON punctuation.
const contents = [
  `export const first = ${JSON.stringify(first.join(" "))}.split(" ");`,
  `export const second = ${JSON.stringify(second.join(" "))}.split(" ");`,
].join("\n");

export const hostWordsVite: VitePlugin = {
  name: "keepalive-host-words",
  load(id) {
    if (id === source) return contents;
    return undefined;
  },
};

export const hostWordsEsbuild: EsbuildPlugin = {
  name: "keepalive-host-words",
  setup(build) {
    build.onLoad({ filter: /[/\\]host-words\.ts$/ }, ({ path }) => {
      if (path === source) return { contents, loader: "js" };
      return undefined;
    });
  },
};
