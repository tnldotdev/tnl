import { Console } from "node:console";
import { readFileSync, writeSync } from "node:fs";
import { pathToFileURL } from "node:url";

type LoaderErrorCode =
  | "evaluation_failed"
  | "import_failed"
  | "invalid_arguments"
  | "invalid_export"
  | "missing_default_export"
  | "unsupported_node";

const [configPath] = process.argv.slice(1);
// keep project logging off the response channel.
globalThis.console = new Console({ stdout: process.stderr, stderr: process.stderr });

try {
  if (configPath === undefined) {
    exitWithError("invalid_arguments");
  }
  const context = deepFreeze(JSON.parse(readFileSync(0, "utf8")) as unknown);
  const [nodeMajor = 0, nodeMinor = 0] = process.versions.node.split(".").map(Number);
  if (nodeMajor < 22 || (nodeMajor === 22 && nodeMinor < 18)) {
    exitWithError("unsupported_node");
  }
  let imported: unknown;
  try {
    imported = await import(pathToFileURL(configPath).href);
  } catch {
    exitWithError("import_failed");
  }
  if (imported === null || typeof imported !== "object" || !("default" in imported)) {
    exitWithError("missing_default_export");
  }
  let value: unknown;
  try {
    value =
      typeof imported.default === "function" ? await imported.default(context) : imported.default;
  } catch {
    exitWithError("evaluation_failed");
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    exitWithError("invalid_export");
  }
  const result = JSON.stringify(value);
  if (result === undefined) {
    exitWithError("evaluation_failed");
  }
  writeSync(1, `R${result}`);
  process.exit(0);
} catch {
  exitWithError("evaluation_failed");
}

function exitWithError(error: LoaderErrorCode): never {
  try {
    writeSync(1, `E${JSON.stringify({ error })}`);
  } finally {
    process.exit(1);
  }
}

function deepFreeze(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }
  for (const child of Object.values(value)) {
    if (child !== null && typeof child === "object") {
      deepFreeze(child);
    }
  }
  return Object.freeze(value);
}
