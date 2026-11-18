import { defineConfig } from "@tnldotdev/tnl/config";

export default defineConfig({
  services: { site: { protocol: "http" } },
  deployments: {
    keepalive: {
      targets: {
        site: {
          type: "app",
          public: true,
          http: { access: "anonymous" },
          hostname: "prod.hosts.keepthisalive.com",
          publisherAliasParent: "hosts.keepthisalive.com",
        },
      },
    },
  },
});
