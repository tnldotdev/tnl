#!/usr/bin/env node

import process from "node:process";
import { resolveNativeBinary } from "../internal/launcher.js";

try {
  const binary = resolveNativeBinary();
  if (process.execve === undefined) {
    throw new Error("Node.js does not support replacing the launcher process");
  }
  process.execve(binary, [binary, ...process.argv.slice(2)], process.env);
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`tnl: ${message}\n`);
  process.exitCode = 1;
}
