import { readFile, writeFile } from "node:fs/promises";

const [file] = process.argv.slice(2);
if (!file) {
  throw new Error("generated Go file is required");
}

const source = await readFile(file, "utf8");
const normalized = source.replaceAll(
  'fmt.Errorf("Header parameter ',
  'fmt.Errorf("header parameter ',
);
await writeFile(file, normalized);
import { installToolFailureHandler } from "./errors.ts";
installToolFailureHandler(import.meta, "tool.input_invalid");
