import assert from "node:assert/strict";
import { renameSync, writeFileSync } from "node:fs";
import { createServer } from "vite";

// observe the real fixture without replacing either tnl development handshake.
const reportPath = process.argv[2];
assert(reportPath, "report path is required");

interface FixtureReport {
  readonly cwd: string;
  readonly hasAccessToken: boolean;
  readonly hasLoginToken: boolean;
  readonly hasRuntimeEnvironment: boolean;
  readonly environmentMetadata?: unknown;
  readonly pid: number;
  readonly protocol: string | undefined;
  readonly socket: string | undefined;
  runtime?: unknown;
  target?: string;
}

const report: FixtureReport = {
  pid: process.pid,
  cwd: process.cwd(),
  protocol: process.env.TNL_DEV_PROTOCOL,
  socket: process.env.TNL_DEV_SOCKET,
  hasAccessToken: Object.hasOwn(process.env, "TNL_ACCESS_TOKEN"),
  hasLoginToken: Object.hasOwn(process.env, "TNL_LOGIN_TOKEN"),
  hasRuntimeEnvironment: Object.hasOwn(process.env, "TNL_PROJECT_RUNTIME"),
  environmentMetadata:
    process.env.TNL_PROJECT_RUNTIME === undefined
      ? undefined
      : (JSON.parse(process.env.TNL_PROJECT_RUNTIME) as unknown),
};
const writeReport = () => {
  writeFileSync(`${reportPath}.tmp`, JSON.stringify(report), { mode: 0o600 });
  renameSync(`${reportPath}.tmp`, reportPath);
};
writeReport();

const server = await createServer();
const definition = server.config.define?.["process.env.TNL_PROJECT_RUNTIME"];
assert(typeof definition === "string", "Vite did not define tnl runtime metadata");
const serializedRuntime = JSON.parse(definition) as unknown;
assert(typeof serializedRuntime === "string", "Vite defined invalid tnl runtime metadata");
report.runtime = JSON.parse(serializedRuntime) as unknown;
writeReport();
await server.listen();
assert(server.httpServer, "Vite did not create an HTTP server");
const address = server.httpServer.address();
assert(address !== null && typeof address !== "string", "Vite did not report a TCP listener");
report.target = `http://${address.address}:${address.port}`;
writeReport();
server.printUrls();
