import { resolve } from "node:path";
import { defineConfig } from "vite";
import { hostWordsVite } from "./scripts/host-words.ts";
import solid from "vite-plugin-solid";

export default defineConfig({
  root: resolve(import.meta.dirname, "src/page"),
  server: { host: "127.0.0.1" },
  plugins: [solid(), hostWordsVite],
  build: {
    outDir: resolve(import.meta.dirname, "dist/site"),
    emptyOutDir: true,
    modulePreload: false,
    rolldownOptions: {
      output: {
        entryFileNames: "app.js",
        chunkFileNames: "chunks/chunk-[hash].js",
        hashCharacters: "hex",
        assetFileNames: "[name][extname]",
      },
    },
  },
});
