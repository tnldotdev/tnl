#!/usr/bin/env node

import process from "node:process";
import { resolveNativeBinary } from "../internal/launcher.js";
import { TnlError, safeTnlMessage, classifyTnlError } from "../errors.js";

try {
  const binary = resolveNativeBinary();
  if (process.execve === undefined) {
    throw new TnlError("sdk.process_unavailable");
  }
  process.execve(binary, [binary, ...process.argv.slice(2)], process.env);
} catch (error) {
  const message = safeTnlMessage(classifyTnlError(error, "sdk.process_unavailable"));
  process.stderr.write(`tnl: ${message}\n`);
  process.exitCode = 1;
}
