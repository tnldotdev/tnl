import { connect } from "cloudflare:sockets";
import { createSocketHost } from "./host.ts";
import type { SocketHost } from "./host.ts";
import { dialWebTCP } from "./host-web.ts";

export function createWorkerHost(signal?: AbortSignal): SocketHost {
  return createSocketHost(
    (address, signal) =>
      dialWebTCP(address, signal, (endpoint) =>
        connect(endpoint, {
          secureTransport: "off",
          allowHalfOpen: true,
        }),
      ),
    signal,
  );
}
