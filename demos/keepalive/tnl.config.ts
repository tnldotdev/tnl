import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig({
  services: { production: { protocol: "http" } },
  deployments: {
    keepalive: {
      targets: {
        production: {
          type: "app",
          public: true,
          http: { access: "anonymous" },
          hostname: "prod.hosts.keepthisalive.com",
          publisherAliasParent: "hosts.keepthisalive.com",
          certificateScope: "hosts.keepthisalive.com",
        },
      },
    },
  },
});
