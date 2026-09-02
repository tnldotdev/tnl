#!/usr/bin/env node

import process from "node:process";
import { resolveNativeBinary } from "../lib/launcher.mjs";

try {
  const binary = resolveNativeBinary();
  process.execve(binary, [binary, ...process.argv.slice(2)], process.env);
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`tnl: ${message}\n`);
  process.exitCode = 1;
}
