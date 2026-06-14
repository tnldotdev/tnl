import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    clearMocks: true,
    exclude: ["**/dist/**", "**/.next/**", "**/node_modules/**"],
    globals: false,
    hookTimeout: 10_000,
    include: [
      "packages/dev/register.test.ts",
      "packages/dev/worktree.test.ts",
      "packages/next/index.test.ts",
      "packages/vite/index.test.ts",
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
