import { createServer } from "vite";
import tnl from "@tnldotdev/tnl/vite";

// the runtime integration supplies real native IPC and reaches this Vite
// listener through the existing control, publisher, relay, and connector fixture.
const server = await createServer({
  root: process.cwd(),
  configFile: false,
  logLevel: "silent",
  plugins: [tnl({ service: "web", preview: "required" })],
  server: { host: "127.0.0.1", port: 0, allowedHosts: ["existing.example"] },
});
let closing: Promise<void> | undefined;
const close = () => (closing ??= server.close());
process.once("SIGINT", () => {
  void close().catch(() => {
    process.exitCode = 1;
  });
});
try {
  await server.listen();
  const address = server.httpServer?.address();
  if (address === undefined || address === null || typeof address === "string")
    throw new Error("Vite did not bind a listener");
  process.stdout.write(`${JSON.stringify({ port: address.port })}\n`);
} catch (error) {
  await close();
  throw error;
}
