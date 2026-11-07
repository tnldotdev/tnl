import { spawn } from "node:child_process";
import { once } from "node:events";
import path from "node:path";
import { parseArgs } from "node:util";
import { parseVariant } from "../../development/connector-wasm/variant.ts";

const { values } = parseArgs({
  options: {
    fixture: { type: "string" },
    queries: { type: "string", default: "1000" },
    warmup: { type: "string", default: "100" },
    repeats: { type: "string" },
    variant: { type: "string", multiple: true },
    variants: { type: "string" },
    cpu: { type: "boolean", default: false },
    streaming: { type: "boolean", default: false },
    "payload-bytes": { type: "string", default: "0" },
  },
});
if (!values.fixture) throw new Error("pass --fixture with the private local fixture file");
const repeats = Number(values.repeats ?? (values.cpu ? "1" : "2"));
if (!Number.isSafeInteger(repeats) || repeats < 1 || repeats > 4)
  throw new Error("repeats must be between 1 and 4");
const chosen =
  (values.variants
    ? values.variants.split(",").map(parseVariant)
    : values.variant?.map(parseVariant)) ??
  (values.cpu
    ? values.streaming
      ? ["optimized", "streaming"]
      : ["baseline", "optimized"]
    : values.streaming
      ? ["optimized", "application-pump", "socket-pump", "streaming"]
      : ["baseline", "buffers", "promises", "optimized"]);
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
        "--payload-bytes",
        values["payload-bytes"],
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
