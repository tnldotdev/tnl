import { rm } from "node:fs/promises";

await Promise.all([
  rm("dist", { force: true, recursive: true }),
  rm("tsconfig.tsbuildinfo", { force: true }),
]);
import { installToolFailureHandler } from "./errors.ts";
installToolFailureHandler(import.meta);
