export const fleets = {
  prod: {
    site: "keepthisalive.com",
    start: "start.keepthisalive.com",
    parent: "prod.hosts.keepthisalive.com",
  },
  ramp: {
    site: "ramp.keepthisalive.com",
    start: "start-ramp.keepthisalive.com",
    parent: "ramp.hosts.keepthisalive.com",
  },
} as const;

// every bundle in a release uses the same fixed peer trust boundary.
declare const KEEPALIVE_FLEET: keyof typeof fleets;
export const fleetName = typeof KEEPALIVE_FLEET === "undefined" ? "prod" : KEEPALIVE_FLEET;
export const fleet = fleets[fleetName];
