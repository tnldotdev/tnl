import { defineConfig } from "vite";
import tnl from "../../dist/index.js";

export default defineConfig({
  plugins: [tnl()],
  server: {
    allowedHosts: ["existing.example"],
    headers: { "X-Tnl-Fixture": "vite" },
    host: "0.0.0.0",
    port: Number(process.env.TNL_FIXTURE_PORT),
    strictPort: false,
  },
});
