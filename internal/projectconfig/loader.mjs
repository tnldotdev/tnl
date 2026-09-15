import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const [configPath] = process.argv.slice(1);

try {
  if (configPath === undefined) {
    throw new Error("the TypeScript loader received invalid arguments");
  }
  const [nodeMajor, nodeMinor] = process.versions.node.split(".").map(Number);
  if (nodeMajor < 22 || (nodeMajor === 22 && nodeMinor < 18)) {
    throw new Error("Node.js 22.18 or newer is required to load tnl.config.ts");
  }
  const imported = await import(pathToFileURL(configPath).href);
  if (!("default" in imported)) {
    throw new Error("tnl.config.ts must have a default export");
  }
  const context = deepFreeze(JSON.parse(readFileSync(4, "utf8")));
  const value =
    typeof imported.default === "function" ? await imported.default(context) : imported.default;
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("tnl.config.ts must export a configuration object or factory");
  }
  writeFileSync(3, JSON.stringify(value), { encoding: "utf8" });
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}

function deepFreeze(value) {
  for (const child of Object.values(value)) {
    if (child !== null && typeof child === "object") {
      deepFreeze(child);
    }
  }
  return Object.freeze(value);
}
