import { expect, it } from "vitest";
import { fleets } from "../src/fleets.ts";
import { hostOrigin } from "../src/peers/host.ts";
import config from "../tnl.config.ts";

it.each(["prod", "ramp"] as const)("isolates the %s deployment and its exact donors", (name) => {
  const deployment = config.deployments[name];
  const service = deployment.targets.production;
  const parent = fleets[name].parent;
  expect(parent).toBe(`${name}.${deployment.domain}`);
  expect(service.publisherAliasParent).toBe(parent);
  expect(service.certificateScope).toBe(parent);
  expect(service.hostname).toBe(`site.${parent}`);
  const donor = `https://p-${"a".repeat(26)}.`;
  expect(hostOrigin(donor + parent, parent)).toBe(true);
  expect(hostOrigin(donor + fleets[name === "prod" ? "ramp" : "prod"].parent, parent)).toBe(false);
});
