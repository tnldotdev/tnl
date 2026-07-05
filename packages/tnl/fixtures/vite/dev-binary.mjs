import { renameSync, writeFileSync } from "node:fs";
import { createServer } from "vite";

// Observe the real fixture without replacing either tnl development handshake.
const reportPath = process.argv[2];
const report = {
  pid: process.pid,
  cwd: process.cwd(),
  protocol: process.env.TNL_DEV_PROTOCOL,
  socket: process.env.TNL_DEV_SOCKET,
  hasAccessToken: Object.hasOwn(process.env, "TNL_ACCESS_TOKEN"),
  hasLoginToken: Object.hasOwn(process.env, "TNL_LOGIN_TOKEN"),
  hasRuntimeEnvironment: Object.hasOwn(process.env, "TNL_PROJECT_RUNTIME"),
};
function writeReport() {
  writeFileSync(`${reportPath}.tmp`, JSON.stringify(report), { mode: 0o600 });
  renameSync(`${reportPath}.tmp`, reportPath);
}
writeReport();

const server = await createServer();
report.runtime = JSON.parse(JSON.parse(server.config.define["process.env.TNL_PROJECT_RUNTIME"]));
writeReport();
await server.listen();
const address = server.httpServer.address();
report.target = `http://${address.address}:${address.port}`;
writeReport();
server.printUrls();
