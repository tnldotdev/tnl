import { expect, it } from "vitest";
import { HOST_PARENT, SHARED_HOST } from "../src/peers/gossip.ts";
import config from "../tnl.config.ts";

it("uses the same delegated hostnames in tnl, the browser, and the proxy", () => {
  const deployment = config.deployments.keepalive;
  const service = deployment.targets.production;

  expect(HOST_PARENT).not.toBe(deployment.domain);
  expect(HOST_PARENT.endsWith(`.${deployment.domain}`)).toBe(true);
  expect(service.publisherAliasParent).toBe(HOST_PARENT);
  expect(service.certificateScope).toBe(HOST_PARENT);
  expect(SHARED_HOST).toBe(`https://${service.hostname}`);
});
