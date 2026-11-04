import { defineConfig } from "vitest/config";

export default defineConfig({
  oxc: { include: /\.[cm]?tsx?$/ },
  test: {
    typecheck: { enabled: true, only: true },
    projects: [
      {
        extends: true,
        test: {
          name: "types",
          typecheck: {
            enabled: true,
            only: true,
            include: ["packages/ts/test/types/*.test-d.{ts,cts}"],
            exclude: ["packages/ts/test/types/runtime-augmented.test-d.*"],
            tsconfig: "packages/ts/type-test.tsconfig.json",
          },
        },
      },
      {
        extends: true,
        test: {
          name: "augmented-types",
          typecheck: {
            enabled: true,
            only: true,
            include: ["packages/ts/test/types/runtime-augmented.test-d.{ts,cts}"],
            tsconfig: "packages/ts/augmented-type-test.tsconfig.json",
          },
        },
      },
    ],
  },
});
