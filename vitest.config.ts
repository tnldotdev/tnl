import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const sourceDirectory = fileURLToPath(new URL("packages/tnl/src/", import.meta.url));

export default defineConfig(({ mode }) => ({
  ...(mode === "coverage"
    ? {
        resolve: {
          alias: [
            // internal tests normally exercise dist too; coverage deliberately uses the
            // same source graph as the public aliases below. Framework subprocesses
            // still resolve the built package, outside Vitest's coverage instrumentation.
            {
              find: /^\.\/dist\/internal\/(dev|runtime)\.js$/,
              replacement: `${sourceDirectory}internal/$1.ts`,
            },
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
        },
      }
    : {}),
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
      "scripts/release-check.test.ts",
      "scripts/runtime-faults.test.ts",
      "scripts/release-version.test.ts",
      "packages/tnl/test-helper.test.ts",
      "packages/tnl/bun.test.ts",
      "packages/tnl/internal-dev.test.ts",
      "packages/tnl/launcher.test.ts",
      "packages/tnl/next.test.ts",
      "packages/tnl/register.test.ts",
      "packages/tnl/runtime.test.ts",
      "packages/tnl/vite.test.ts",
    ],
    isolate: true,
    mockReset: true,
    pool: "forks",
    restoreMocks: true,
    setupFiles: ["packages/tnl/test-helper/environment-setup.ts"],
    testTimeout: 10_000,
    unstubEnvs: true,
    unstubGlobals: true,
  },
}));
