import { expect, it } from "vitest";
import { turnWarning } from "../src/page/attention.ts";
import { HOST_TURN_MS, TURN_WARNING_MS, hostTarget, turnLength } from "../src/policy.ts";

it("warns once per serving turn, including a late tick but never after expiry", () => {
  const warn = turnWarning();
  expect(turnLength(false)).toBe(15 * 60_000);
  expect(turnLength(true)).toBe(60 * 60_000);
  expect(warn("one", HOST_TURN_MS, HOST_TURN_MS - TURN_WARNING_MS - 1)).toBe(false);
  expect(warn("one", HOST_TURN_MS, HOST_TURN_MS - TURN_WARNING_MS + 900)).toBe(true);
  expect(warn("one", HOST_TURN_MS, HOST_TURN_MS - 1)).toBe(false);
  expect(warn("suspended", HOST_TURN_MS, HOST_TURN_MS + 1)).toBe(false);
  expect(warn("next", HOST_TURN_MS, HOST_TURN_MS - TURN_WARNING_MS)).toBe(true);
});

it("estimates redundancy from observed tabs rather than a fixed fleet size", () => {
  expect(hostTarget(0)).toBe(3);
  expect(hostTarget(200)).toBe(4);
  expect(hostTarget(250_000)).toBe(5_000);
});
