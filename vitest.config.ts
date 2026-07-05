import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const sourceDirectory = fileURLToPath(new URL("packages/tnl/src/", import.meta.url));

export default defineConfig({
  resolve:
    process.env.TNL_TEST_COVERAGE === "1"
      ? {
          alias: [
            {
              find: /^@tnldotdev\/tnl\/next$/,
              replacement: `${sourceDirectory}next.ts`,
            },
            {
              find: /^@tnldotdev\/tnl\/vite$/,
              replacement: `${sourceDirectory}vite.ts`,
            },
            {
              find: /^@tnldotdev\/tnl$/,
              replacement: `${sourceDirectory}index.ts`,
            },
          ],
        }
      : undefined,
  test: {
    clearMocks: true,
    coverage: {
      include: ["packages/tnl/src/**/*.ts"],
      provider: "v8",
      reporter: ["text", "html", "lcov"],
      reportsDirectory: "coverage/typescript",
    },
    exclude: ["**/dist/**", "**/.next/**", "**/node_modules/**"],
    globals: false,
    hookTimeout: 10_000,
    include: [
      "packages/tnl/internal-dev.test.ts",
      "packages/tnl/next.test.ts",
      "packages/tnl/runtime.test.ts",
      "packages/tnl/vite.test.ts",
    ],
    isolate: true,
    mockReset: true,
    pool: "forks",
    restoreMocks: true,
    testTimeout: 10_000,
    unstubEnvs: true,
    unstubGlobals: true,
  },
});
