import { spawn } from "node:child_process";
import { once } from "node:events";
import path from "node:path";
import { parseArgs } from "node:util";
import { parseVariant, variants } from "../../development/connector-wasm/variant.ts";

const { values } = parseArgs({
  options: {
    fixture: { type: "string" },
    queries: { type: "string", default: "1000" },
    warmup: { type: "string", default: "100" },
    repeats: { type: "string", default: "2" },
    variant: { type: "string", multiple: true },
    cpu: { type: "boolean", default: false },
  },
});
if (!values.fixture) throw new Error("pass --fixture with the private local fixture file");
const repeats = Number(values.repeats);
if (!Number.isSafeInteger(repeats) || repeats < 1 || repeats > 4)
  throw new Error("repeats must be between 1 and 4");
const chosen = values.variant?.map(parseVariant) ?? [...variants];
const root = path.resolve(import.meta.dirname, "../..");
const stem = `profile-${Date.now()}`;
for (let repeat = 0; repeat < repeats; repeat++) {
  // reverse the second pass rather than consistently favoring a warm host.
  for (const variant of repeat % 2 ? chosen.toReversed() : chosen) {
    const profileFile = path.join(
      root,
      "development/connector-wasm/dist/profiles",
      `${stem}-${repeat}-${variant}.cpuprofile`,
    );
    const child = spawn(
      process.execPath,
      [
        "development/connector-wasm/node.ts",
        "--fixture",
        values.fixture,
        "--queries",
        values.queries,
        "--warmup",
        values.warmup,
        "--variant",
        variant,
        "--diagnostics",
        ...(values.cpu
          ? [
              "--wasm",
              "development/connector-wasm/dist/connector-profile.wasm",
              "--cpu-profile",
              profileFile,
            ]
          : []),
      ],
      { cwd: root, stdio: "inherit" },
    );
    const onSignal = (): void => {
      child.kill("SIGTERM");
    };
    process.once("SIGTERM", onSignal);
    process.once("SIGINT", onSignal);
    try {
      const [code, signal] = await once(child, "close");
      if (code !== 0 || signal !== null) throw new Error(`profiling ${variant} did not complete`);
    } finally {
      process.removeListener("SIGTERM", onSignal);
      process.removeListener("SIGINT", onSignal);
    }
  }
}
