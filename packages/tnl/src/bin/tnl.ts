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
  let message = "launcher failed";
  try {
    message = error instanceof Error ? error.message : String(error);
  } catch {}
  message = [...message]
    .map((character) => {
      const codePoint = character.codePointAt(0);
      return codePoint !== undefined &&
        (codePoint <= 0x1f ||
          (codePoint >= 0x7f && codePoint <= 0x9f) ||
          codePoint === 0x2028 ||
          codePoint === 0x2029)
        ? " "
        : character;
    })
    .join("")
    .trim();
  if (message === "") message = "launcher failed";
  process.stderr.write(`tnl: ${message}\n`);
  process.exitCode = 1;
}
