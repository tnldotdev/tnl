import { NOTFOUND } from "node:dns";
import { Resolver } from "node:dns/promises";
import { defineConfig } from "vite";
import tnl from "@tnldotdev/tnl/vite";

// keep the hosted preview fixture off live dns, including after config reloads.
const resolve = Resolver.prototype.resolve;
Resolver.prototype.resolve = async function (this: Resolver, hostname: string, type: string = "A") {
  if (hostname === "api.member.example") {
    throw Object.assign(new Error("fixture hostname not found"), { code: NOTFOUND });
  }
  return resolve.call(this, hostname, type);
} as typeof resolve;

export default defineConfig({
  plugins: [tnl()],
  server: {
    allowedHosts: ["existing.example"],
    headers: { "X-Tnl-Fixture": "vite" },
    host: process.env.TNL_FIXTURE_HOST ?? "0.0.0.0",
    port: Number(process.env.TNL_FIXTURE_PORT),
    strictPort: false,
  },
});
