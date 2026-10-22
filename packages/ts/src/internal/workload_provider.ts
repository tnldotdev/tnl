import { constants } from "node:fs";
import { open, realpath } from "node:fs/promises";
import * as path from "node:path";
import { Agent, fetch as nodeFetch } from "undici";
import * as z from "zod";
import { privateTnlError, TnlError } from "../errors.js";
import type { WorkloadOptions } from "../workload.js";
import {
  manifestSchema,
  parseWorkload,
  type Workload,
  type WorkloadManifest,
} from "./workload_contract.js";
import { validServiceName } from "./runtime.js";

let configuration: WorkloadOptions | undefined;

/** register a fixed request-scoped source, never a mutable current token. */
export function configureWorkload(options: WorkloadOptions): void {
  if (
    typeof options !== "object" ||
    options === null ||
    !validServiceName(options.name) ||
    (typeof options.token !== "function" && typeof options.tokenFile !== "string") ||
    Object.keys(options).some((key) => key !== "name" && key !== "token" && key !== "tokenFile") ||
    (options.token !== undefined && options.tokenFile !== undefined) ||
    (options.tokenFile !== undefined &&
      (options.tokenFile.length === 0 ||
        options.tokenFile.length > 4096 ||
        options.tokenFile.includes("\0"))) ||
    (configuration !== undefined &&
      (configuration.name !== options.name ||
        configuration.token !== options.token ||
        configuration.tokenFile !== options.tokenFile))
  )
    throw new TnlError("sdk.workload_required");
  configuration = Object.freeze({ ...options });
}

function runtimeProviders(): string[] {
  return [
    ...(process.env.VERCEL === "1" ? ["vercel"] : []),
    ...(process.env.FLY_APP_NAME ? ["fly"] : []),
    ...(process.env.GITHUB_ACTIONS === "true" ? ["github"] : []),
  ];
}

export function usesWorkload(): boolean {
  return (
    process.env.TNL_CONNECTION_HANDLE === undefined &&
    (process.env.TNL_WORKLOAD !== undefined ||
      configuration !== undefined ||
      runtimeProviders().length > 0)
  );
}

export async function boundedFile(
  filename: string,
  maximum: number,
  owned = false,
): Promise<string> {
  const file = await open(
    filename,
    constants.O_RDONLY | constants.O_NONBLOCK | (owned ? constants.O_NOFOLLOW : 0),
  );
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > maximum) throw new TnlError("sdk.workload_manifest_invalid");
    const buffer = Buffer.alloc(maximum + 1);
    let total = 0;
    while (total < buffer.length) {
      const { bytesRead } = await file.read(buffer, total, buffer.length - total, null);
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    if (total > maximum) throw new TnlError("sdk.workload_manifest_invalid");
    return new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, total));
  } finally {
    await file.close();
  }
}

export async function selectWorkload(): Promise<{
  manifest: WorkloadManifest;
  name: string;
  selected: Workload;
  directory: string;
}> {
  let manifest: WorkloadManifest;
  let directory: string;
  try {
    directory = await realpath(process.cwd());
    const filename = path.join(directory, ".tnl/generated/workloads.json");
    // only this server artifact file can give acquisition instructions. public
    // metadata, config files, git, and .vercel/project.json are never consulted.
    if ((await realpath(filename)) !== filename)
      throw new TnlError("sdk.workload_manifest_invalid");
    manifest = parseWorkload(
      manifestSchema,
      JSON.parse(await boundedFile(filename, 128 * 1024, true)),
      "sdk.workload_manifest_invalid",
    );
  } catch (cause) {
    throw privateTnlError("sdk.workload_manifest_invalid", cause);
  }
  const explicit = process.env.TNL_WORKLOAD ?? configuration?.name;
  if (configuration !== undefined && explicit !== configuration.name)
    throw new TnlError("sdk.workload_required");
  const providers = runtimeProviders();
  const candidates = Object.entries(manifest.workloads).filter(
    ([, w]) => providers.length === 1 && providers[0] === w.provider,
  );
  const name = explicit ?? (candidates.length === 1 ? candidates[0]?.[0] : undefined);
  const selected =
    name === undefined || !Object.hasOwn(manifest.workloads, name)
      ? undefined
      : manifest.workloads[name];
  if (name === undefined || !validServiceName(name) || selected === undefined)
    throw new TnlError("sdk.workload_required");
  return { manifest, name, selected, directory };
}

export function boundedAssertion(raw: unknown): string {
  if (typeof raw !== "string") throw new TnlError("sdk.workload_assertion_unavailable");
  const token = raw.trim();
  if (!token || Buffer.byteLength(token) > 32768 || token.includes("\0") || /\s/.test(token))
    throw new TnlError("sdk.workload_assertion_unavailable");
  return token;
}

export async function boundedText(
  response: {
    readonly body: {
      getReader(): {
        read(): Promise<{ readonly done: boolean; readonly value?: unknown }>;
        cancel(): Promise<void>;
        releaseLock(): void;
      };
    } | null;
  },
  maximum: number,
): Promise<string> {
  const reader = response.body?.getReader();
  if (reader === undefined) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new TnlError("sdk.workload_response_invalid");
      total += value.byteLength;
      if (total > maximum) throw new TnlError("sdk.workload_response_invalid");
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
}

export async function flyAssertion(
  audience: string,
  signal: AbortSignal,
  socketPath = "/.fly/api",
): Promise<string> {
  const dispatcher = new Agent({ connect: { socketPath }, connections: 1, pipelining: 1 });
  try {
    const response = await nodeFetch("http://localhost/v1/tokens/oidc", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ aud: audience }),
      redirect: "manual",
      signal,
      dispatcher,
    });
    if (response.status !== 200) {
      await response.body?.cancel();
      throw new TnlError("sdk.workload_assertion_unavailable");
    }
    return boundedAssertion(await boundedText(response, 32768));
  } finally {
    await dispatcher.close();
  }
}

async function githubToken(audience: string, signal: AbortSignal): Promise<string> {
  if (process.env.GITHUB_ACTIONS !== "true")
    throw new TnlError("sdk.workload_assertion_unavailable");
  const url = new URL(process.env.ACTIONS_ID_TOKEN_REQUEST_URL ?? "");
  const bearer = boundedAssertion(process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN);
  if (url.protocol !== "https:" || url.username || url.password || url.hash)
    throw new TnlError("sdk.workload_assertion_unavailable");
  url.searchParams.set("audience", audience);
  const response = await globalThis.fetch(url, {
    headers: { authorization: `Bearer ${bearer}` },
    redirect: "manual",
    signal,
  });
  if (response.status !== 200) {
    await response.body?.cancel();
    throw new TnlError("sdk.workload_assertion_unavailable");
  }
  const body = parseWorkload(
    z.strictObject({ value: z.string() }),
    JSON.parse(await boundedText(response, 40 * 1024)),
    "sdk.workload_assertion_unavailable",
  );
  return boundedAssertion(body.value);
}

export async function acquireAssertion(
  name: string,
  selected: Workload,
  directory: string,
  signal: AbortSignal,
): Promise<string> {
  try {
    signal.throwIfAborted();
    const source = configuration?.name === name ? configuration : undefined;
    if (source !== undefined) {
      if (
        selected.acquisition.method !== "callback" &&
        selected.acquisition.method !== "github-actions"
      )
        throw new TnlError("sdk.workload_assertion_unavailable");
      return boundedAssertion(
        source.token === undefined
          ? await boundedFile(path.resolve(directory, source.tokenFile), 32768)
          : await source.token(),
      );
    }
    switch (selected.acquisition.method) {
      case "vercel-oidc": {
        const { getContext, getVercelOidcToken } = await import("@vercel/oidc");
        const current = getContext().headers?.["x-vercel-oidc-token"];
        if (current !== undefined) {
          boundedAssertion(current);
          // the documented expiry buffer disables development refresh here.
          // only control decides token validity; expired assertions must not
          // trigger .vercel discovery, CLI credentials, or global token writes.
          return boundedAssertion(
            await getVercelOidcToken({ expirationBufferMs: Number.NEGATIVE_INFINITY }),
          );
        }
        // the helper documents file-before-env fallback. read those bounded
        // sources directly so a missing token never invokes its CLI refresh.
        const file = process.env.VERCEL_OIDC_TOKEN_FILE;
        return boundedAssertion(
          file
            ? await boundedFile(path.resolve(directory, file), 32768)
            : process.env.VERCEL_OIDC_TOKEN,
        );
      }
      case "fly-machine-api":
        if (selected.acquisition.audience === undefined)
          throw new TnlError("sdk.workload_assertion_unavailable");
        return await flyAssertion(selected.acquisition.audience, signal);
      case "github-actions":
        if (selected.acquisition.audience === undefined)
          throw new TnlError("sdk.workload_assertion_unavailable");
        return await githubToken(selected.acquisition.audience, signal);
      case "token-file":
        if (selected.acquisition.token_file === undefined)
          throw new TnlError("sdk.workload_assertion_unavailable");
        return boundedAssertion(
          await boundedFile(path.resolve(directory, selected.acquisition.token_file), 32768),
        );
      case "callback":
        throw new TnlError("sdk.workload_assertion_unavailable");
    }
  } catch (cause) {
    if (signal.aborted) throw signal.reason;
    throw privateTnlError("sdk.workload_assertion_unavailable", cause);
  }
}
