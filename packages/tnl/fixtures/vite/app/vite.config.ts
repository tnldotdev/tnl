import { defineConfig } from "vite";
import tnl from "@tnldotdev/tnl/vite";

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
