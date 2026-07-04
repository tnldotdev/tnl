import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    clearMocks: true,
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
