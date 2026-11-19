import * as z from "zod";

export const RELEASE_PATH = "/__keepalive/release";
export const ARTIFACT_PREFIX = "/__keepalive/artifact";
export const WORKER_PATH = "/hosting/worker.js";
export const WASM_PATH = "/hosting/wasm/publisher.wasm";
export const MAX_ASSET_BYTES = 32 * 1024 * 1024;
export const MAX_RELEASE_BYTES = 40 * 1024 * 1024;
export const MAX_MANIFEST_BYTES = 24 * 1024;

const media = new Map([
  ["css", "text/css; charset=utf-8"],
  ["html", "text/html; charset=utf-8"],
  ["js", "text/javascript; charset=utf-8"],
  ["svg", "image/svg+xml"],
  ["wasm", "application/wasm"],
  ["woff2", "font/woff2"],
]);
const sha256Hex = /^[a-f0-9]{64}$/;

const assetSchema = z.strictObject({
  path: z
    .string()
    .max(160)
    .regex(/^(?:\/[a-z0-9][a-z0-9_-]*)*\/[a-z0-9][a-z0-9_-]*\.[a-z0-9]+$/)
    .refine((path) => contentType(path) !== undefined),
  size: z.int().min(1).max(MAX_ASSET_BYTES),
  sha256: z.string().regex(sha256Hex),
});

export const releaseSchema = z.strictObject({
  id: z.string().regex(sha256Hex),
  assets: z.array(assetSchema).max(64),
});

export type Asset = z.infer<typeof assetSchema>;
export type Release = z.infer<typeof releaseSchema>;

export function contentType(path: string): string | undefined {
  return media.get(path.slice(path.lastIndexOf(".") + 1));
}

export async function digest(bytes: BufferSource): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

export async function parseRelease(value: unknown): Promise<Release> {
  const release = releaseSchema.parse(value);
  const { assets } = release;
  const paths = new Set(assets.map((asset) => asset.path));
  const total = assets.reduce((sum, asset) => sum + asset.size, 0);
  if (
    paths.size !== assets.length ||
    total > MAX_RELEASE_BYTES ||
    !["/index.html", WORKER_PATH, WASM_PATH].every((path) => paths.has(path)) ||
    (await digest(new TextEncoder().encode(JSON.stringify(assets)))) !== release.id
  ) {
    throw new Error("Invalid release contents.");
  }
  return release;
}

export async function readBytes(
  response: Response,
  limit: number,
  signal?: AbortSignal,
  exact?: number,
  onProgress?: (bytes: number) => void,
): Promise<Uint8Array<ArrayBuffer>> {
  const reader = response.body?.getReader();
  if (reader === undefined) throw new Error("Response has no body.");
  const cancel = () => void reader.cancel().catch(() => {});
  signal?.addEventListener("abort", cancel, { once: true });
  let complete = false;
  try {
    if (response.status !== 200) throw new Error("Response is not available.");
    const bytes = new Uint8Array(exact ?? limit);
    let offset = 0;
    for (;;) {
      signal?.throwIfAborted();
      const { done, value } = await reader.read();
      signal?.throwIfAborted();
      if (done) break;
      if (value.byteLength > bytes.byteLength - offset) throw new Error("Response exceeds limit.");
      bytes.set(value, offset);
      offset += value.byteLength;
      onProgress?.(offset);
    }
    complete = true;
    if (exact !== undefined && offset !== exact) throw new Error("Response size does not match.");
    return bytes.subarray(0, offset);
  } finally {
    signal?.removeEventListener("abort", cancel);
    if (!complete) cancel();
    reader.releaseLock();
  }
}

export async function verifyAsset(
  asset: Asset,
  bytes: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  if (asset.size !== bytes.byteLength || asset.sha256 !== (await digest(bytes))) {
    throw new Error("Response does not match the release.");
  }
  return bytes;
}

export async function readAssetResponse(
  asset: Asset,
  response: Response,
  signal: AbortSignal,
  onProgress?: (bytes: number) => void,
) {
  return verifyAsset(asset, await readBytes(response, asset.size, signal, asset.size, onProgress));
}

export async function readJSON(
  response: Response,
  limit: number,
  signal?: AbortSignal,
): Promise<unknown> {
  return JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(await readBytes(response, limit, signal)),
  );
}
