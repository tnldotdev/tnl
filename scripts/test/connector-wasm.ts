import { spawn } from "node:child_process";
import { once } from "node:events";
import path from "node:path";
import { parseArgs } from "node:util";

const { values } = parseArgs({
  options: {
    runtime: { type: "string", default: "node" },
    fixture: { type: "string" },
    queries: { type: "string", default: "10" },
  },
});
if (!values.fixture || !["node", "bun", "workerd"].includes(values.runtime))
  throw new Error("pass --runtime node|bun|workerd and --fixture with a private fixture file");
const queries = Number(values.queries);
if (!Number.isSafeInteger(queries) || queries < 1 || queries > 10_000)
  throw new Error("--queries must be an integer between 1 and 10000");
const root = path.resolve(import.meta.dirname, "../..");
const worker = values.runtime === "workerd";
const command = values.runtime === "bun" ? "bun" : process.execPath;
const child = spawn(
  command,
  [
    worker ? "scripts/test/connector-wasm-workerd.ts" : "development/connector-wasm/node.ts",
    "--fixture",
    values.fixture,
    "--queries",
    String(queries),
  ],
  { cwd: root, stdio: "inherit" },
);
const forwardSignal = (): void => {
  child.kill("SIGTERM");
};
process.once("SIGTERM", forwardSignal);
process.once("SIGINT", forwardSignal);
try {
  const [code, signal] = (await once(child, "close")) as [number | null, string | null];
  if (code !== 0 || signal !== null) process.exitCode = 1;
} finally {
  process.removeListener("SIGTERM", forwardSignal);
  process.removeListener("SIGINT", forwardSignal);
}
