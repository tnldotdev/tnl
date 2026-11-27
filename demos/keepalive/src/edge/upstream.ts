import { runIDSchema } from "../peers/gossip.ts";

const maxErrorBytes = 4_096;

export function rayID(value: string | null) {
  return value !== null && /^[a-f0-9]{16}(?:-[a-z]{3})?$/i.test(value) ? value : null;
}

function boundedHeader(headers: Headers, name: string, pattern: RegExp) {
  const value = headers.get(name);
  return value !== null && pattern.test(value) ? value : null;
}

async function errorBody(response: Response, signal: AbortSignal) {
  if (response.body === null) return "empty";
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(100)]);
  const reader = response.body.getReader();
  const cancel = () => void reader.cancel().catch(() => {});
  deadline.addEventListener("abort", cancel, { once: true });
  try {
    const bytes = new Uint8Array(maxErrorBytes);
    let length = 0;
    while (length < bytes.length) {
      deadline.throwIfAborted();
      const { done, value } = await reader.read();
      deadline.throwIfAborted();
      if (done) break;
      const prefix = value.subarray(0, bytes.length - length);
      bytes.set(prefix, length);
      length += prefix.length;
    }
    if (length === 0) return "empty";
    const text = new TextDecoder().decode(bytes.subarray(0, length));
    if (text.trim() === "service HTTP authorization is unavailable; retry")
      return "tnl_authorization";
    if (/\bcloudflare\b/i.test(text)) return "cloudflare";
    if (/\bupstream connect error\b|\bno healthy upstream\b/i.test(text)) return "proxy_error";
    return "other";
  } catch {
    return "unread";
  } finally {
    deadline.removeEventListener("abort", cancel);
    cancel();
    reader.releaseLock();
  }
}

export async function upstreamFailure(response: Response, signal: AbortSignal) {
  const { headers } = response;
  return {
    ray: rayID(headers.get("CF-Ray")),
    tnlErrorCode: boundedHeader(headers, "Tnl-Error-Code", /^TNL_[A-Z0-9_]{1,76}$/),
    publisher: headers.get("X-Keepalive-Origin") === "browser",
    runID: runIDSchema.safeParse(headers.get("X-Keepalive-Run")).data ?? null,
    server: boundedHeader(headers, "Server", /^(?:cloudflare(?:-nginx)?|envoy|nginx)$/i),
    cfErrorType: boundedHeader(headers, "CF-Error-Type", /^[a-z0-9_-]{1,48}$/i),
    cfErrorOrigin: boundedHeader(headers, "CF-Error-Origin", /^[a-z0-9_.-]{1,48}$/i),
    visitorConnectionID: boundedHeader(headers, "X-Keepalive-Ramp-Visitor", /^vc_[a-z0-9]{22}$/i),
    capacityFailure: boundedHeader(headers, "X-Keepalive-Ramp-Capacity", /^[a-z0-9_]{1,48}$/i),
    body: await errorBody(response, signal),
  };
}
