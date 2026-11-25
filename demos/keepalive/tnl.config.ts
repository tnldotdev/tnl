import { defineConfig } from "@tnldotdev/tnl/config";
import { fleets } from "./src/fleets.ts";

function deployment(parent: string) {
  return {
    domain: "hosts.keepthisalive.com",
    targets: {
      production: {
        type: "app",
        public: true,
        http: { access: "anonymous" },
        hostname: `site.${parent}`,
        publisherAliasParent: parent,
        certificateScope: parent,
      },
    },
  } as const;
}

export default defineConfig({
  services: { production: { protocol: "http" } },
  deployments: {
    prod: deployment(fleets.prod.parent),
    ramp: deployment(fleets.ramp.parent),
    // keep the previous deployment addressable during the cutover.
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
