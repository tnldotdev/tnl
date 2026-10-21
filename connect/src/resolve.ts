import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { access, chmod, copyFile, mkdir, readFile, realpath, stat } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import * as z from "zod";
import { command } from "./native.js";
import { ActionError, checkCancelled, ownedError } from "./errors.js";

export const exactVersion =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const releaseVersion = z
  .string()
  .max(128)
  .regex(exactVersion)
  .refine((value) => {
    const prerelease = value.slice(value.indexOf("-") + 1);
    return !value.includes("-") || prerelease.split(".").every((part) => !/^0\d+$/.test(part));
  });
const manifest = z.object({
  name: z.string(),
  version: releaseVersion,
  optionalDependencies: z.record(z.string(), z.string()).optional(),
  tnl: z
    .object({
      binarySha256: z
        .string()
        .regex(/^[a-f0-9]{64}$/)
        .optional(),
    })
    .optional(),
});
const legalFiles = ["LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"];

// resolve from the consumer, then from the launcher manifest, not the action's
// node_modules or a hoisted platform package. this also follows pnpm symlinks.
export async function installedBinary(
  directory: string,
  expectedVersion?: string,
): Promise<string> {
  try {
    const consumer = createRequire(path.join(directory, "__tnl_action_resolve__.cjs"));
    const entry = await realpath(consumer.resolve("@tnldotdev/tnl"));
    let root = path.dirname(entry);
    for (;;) {
      let value: unknown;
      try {
        value = JSON.parse(await readFile(path.join(root, "package.json"), "utf8")) as unknown;
      } catch (cause) {
        /* an export can live below a directory without a manifest */
        if (!(cause instanceof Error && "code" in cause && cause.code === "ENOENT")) throw cause;
      }
      const parsed = manifest.safeParse(value);
      const identity = z.object({ name: z.literal("@tnldotdev/tnl") }).safeParse(value);
      if (identity.success) {
        if (!parsed.success)
          throw new ActionError("TNL_ACTION_BINARY_UNAVAILABLE", { cause: parsed.error });
        break;
      }
      const parent = path.dirname(root);
      if (parent === root) throw new ActionError("TNL_ACTION_BINARY_UNAVAILABLE");
      root = parent;
    }
    const mainPath = path.join(root, "package.json");
    const main = manifest.parse(JSON.parse(await readFile(mainPath, "utf8")) as unknown);
    if (expectedVersion !== undefined && main.version !== expectedVersion)
      throw new ActionError("TNL_ACTION_BINARY_UNAVAILABLE");
    if (!["linux", "darwin"].includes(process.platform) || !["arm64", "x64"].includes(process.arch))
      throw new ActionError("TNL_ACTION_BINARY_UNAVAILABLE");
    const name = `@tnldotdev/tnl-${process.platform}-${process.arch}`;
    if (main.optionalDependencies?.[name] !== main.version)
      throw new ActionError("TNL_ACTION_BINARY_UNAVAILABLE");
    const nativePath = createRequire(mainPath).resolve(`${name}/package.json`);
    const native = manifest.parse(JSON.parse(await readFile(nativePath, "utf8")) as unknown);
    if (native.name !== name || native.version !== main.version)
      throw new ActionError("TNL_ACTION_BINARY_UNAVAILABLE");
    const binary = await realpath(path.join(path.dirname(nativePath), "bin/tnl"));
    await access(binary, constants.X_OK);
    const digest = native.tnl?.binarySha256;
    if (
      digest === undefined ||
      createHash("sha256")
        .update(await readFile(binary))
        .digest("hex") !== digest
    )
      throw new ActionError("TNL_ACTION_BINARY_UNAVAILABLE");
    return binary;
  } catch (cause) {
    throw ownedError(cause, "TNL_ACTION_BINARY_UNAVAILABLE");
  }
}

export async function pinBinary(
  source: string,
  session: string,
  requireLegal: boolean,
): Promise<string> {
  try {
    const resolved = await realpath(source);
    if (!(await stat(resolved)).isFile()) throw new ActionError("TNL_ACTION_BINARY_COPY_FAILED");
    await access(resolved, constants.X_OK);
    const directory = path.join(session, "binary");
    await mkdir(directory, { mode: 0o700 });
    const binary = path.join(directory, "tnl");
    await copyFile(resolved, binary, constants.COPYFILE_EXCL);
    await chmod(binary, 0o700);
    for (const file of legalFiles) {
      let found = false;
      let missing: unknown;
      for (const parent of [path.dirname(resolved), path.dirname(path.dirname(resolved))]) {
        try {
          await copyFile(
            path.join(parent, file),
            path.join(directory, file),
            constants.COPYFILE_EXCL,
          );
          found = true;
          break;
        } catch (cause) {
          /* explicit cli-path may be a locally built binary */
          if (!(cause instanceof Error && "code" in cause && cause.code === "ENOENT"))
            throw new ActionError("TNL_ACTION_BINARY_COPY_FAILED", { cause });
          missing = cause;
        }
      }
      if (!found && requireLegal)
        throw new ActionError("TNL_ACTION_LEGAL_FILES_MISSING", { cause: missing });
    }
    return binary;
  } catch (cause) {
    throw ownedError(cause, "TNL_ACTION_BINARY_COPY_FAILED");
  }
}

export async function selectBinary(options: {
  directory: string;
  session: string;
  version: string;
  cliPath: string;
  signal: AbortSignal;
}): Promise<string> {
  checkCancelled(options.signal);
  if (options.version && options.cliPath)
    throw new ActionError("TNL_ACTION_BINARY_SELECTION_INVALID");
  let directory = options.directory;
  if (options.version) {
    if (!releaseVersion.safeParse(options.version).success)
      throw new ActionError("TNL_ACTION_VERSION_INVALID");
    directory = path.join(options.session, "install");
    try {
      await mkdir(directory, { mode: 0o700 });
      // npm verifies registry tarball integrity. no npx auto-install, lifecycle
      // scripts, remote shell installer, or implicit latest fallback is involved.
      await command(
        "npm",
        [
          "install",
          "--prefix",
          directory,
          "--ignore-scripts",
          "--no-audit",
          "--no-fund",
          "--include=optional",
          "--save-exact",
          "--registry=https://registry.npmjs.org",
          `@tnldotdev/tnl@${options.version}`,
        ],
        {
          cwd: directory,
          timeout: 120_000,
          signal: options.signal,
        },
      );
    } catch (cause) {
      if (cause instanceof ActionError && cause.code === "TNL_ACTION_CANCELLED") throw cause;
      throw new ActionError("TNL_ACTION_INSTALL_FAILED", { cause });
    }
  }
  checkCancelled(options.signal);
  const source = options.cliPath
    ? path.resolve(options.directory, options.cliPath)
    : await installedBinary(directory, options.version || undefined);
  return await pinBinary(source, options.session, !options.cliPath);
}
