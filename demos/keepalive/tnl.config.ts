import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig({
  services: { production: { protocol: "http" } },
  deployments: {
    keepalive: {
      domain: "hosts.keepthisalive.com",
      targets: {
        production: {
          type: "app",
          public: true,
          http: { access: "anonymous" },
          hostname: "prod.live.hosts.keepthisalive.com",
          publisherAliasParent: "live.hosts.keepthisalive.com",
          certificateScope: "live.hosts.keepthisalive.com",
        },
      },
    },
  },
});
