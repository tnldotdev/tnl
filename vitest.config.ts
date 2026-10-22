import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const sourceDirectory = fileURLToPath(new URL("packages/ts/src/", import.meta.url));

export default defineConfig(({ mode }) => ({
  ...(mode === "coverage"
    ? {
        resolve: {
          alias: [
            {
              find: /^\.\/internal\/connector\/connection_bridge\.js$/,
              replacement: fileURLToPath(
                new URL("packages/ts/test/helpers/source-connection-bridge.ts", import.meta.url),
              ),
            },
            // internal tests normally exercise dist too; coverage deliberately uses the
            // same source graph as the public aliases below. Framework subprocesses
            // still resolve the built package, outside Vitest's coverage instrumentation.
            {
              find: /^\.\.\/\.\.\/dist\/(errors|internal\/[a-z_/-]+)\.js$/,
              replacement: `${sourceDirectory}$1.ts`,
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
              find: /^@tnldotdev\/tnl\/workload$/,
              replacement: `${sourceDirectory}workload.ts`,
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
      include: ["packages/ts/src/**/*.ts"],
      provider: "v8",
      reporter: ["text", "html", "lcov"],
      reportsDirectory: "coverage/typescript",
    },
    exclude: ["**/dist/**", "**/.next/**", "**/node_modules/**"],
    globals: false,
    hookTimeout: 10_000,
    projects: [
      {
        extends: true,
        test: {
          name: "node",
          include: ["**/*.test.{ts,tsx}"],
          exclude: [
            "**/dist/**",
            "**/.next/**",
            "**/node_modules/**",
            "**/*.dom.test.ts",
            "**/*.dom.test.tsx",
            "**/*.browser.test.ts",
          ],
        },
      },
      {
        extends: true,
        resolve: {
          alias: [
            { find: /^react$/, replacement: "preact/compat" },
            { find: /^react\/jsx-runtime$/, replacement: "preact/jsx-runtime" },
          ],
        },
        test: {
          name: "dom",
          environment: "jsdom",
          include: ["**/*.dom.test.ts", "**/*.dom.test.tsx"],
          server: { deps: { inline: ["@tanstack/react-query"] } },
        },
      },
    ],
    isolate: true,
    mockReset: true,
    pool: "forks",
    restoreMocks: true,
    setupFiles: ["packages/ts/test/helpers/environment-setup.ts"],
    testTimeout: 10_000,
    unstubEnvs: true,
    unstubGlobals: true,
  },
}));
