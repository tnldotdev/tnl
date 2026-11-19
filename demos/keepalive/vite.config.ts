import { resolve } from "node:path";
import { defineConfig } from "vite";

export default defineConfig({
  root: resolve(import.meta.dirname, "src/page"),
  server: { host: "127.0.0.1" },
  build: {
    outDir: resolve(import.meta.dirname, "dist/site"),
    emptyOutDir: true,
    modulePreload: false,
    rolldownOptions: {
      output: { entryFileNames: "app.js", assetFileNames: "[name][extname]" },
    },
  },
});
