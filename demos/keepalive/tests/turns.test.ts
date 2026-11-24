import { expect, it } from "vitest";
import { turnWarning } from "../src/page/attention.ts";
import { HOST_TURN_MS, TURN_WARNING_MS, hostTarget, turnLength } from "../src/policy.ts";

it("warns once at each of the last five minutes, never at expiry", () => {
  const warn = turnWarning();
  expect(turnLength(false)).toBe(15 * 60_000);
  expect(turnLength(true)).toBe(60 * 60_000);
  expect(warn("one", HOST_TURN_MS, HOST_TURN_MS - TURN_WARNING_MS - 1)).toBe(false);
  for (const minute of [5, 4, 3, 2, 1]) {
    const at = HOST_TURN_MS - minute * 60_000;
    expect(warn("one", HOST_TURN_MS, at + 900)).toBe(true);
    expect(warn("one", HOST_TURN_MS, at + 950)).toBe(false);
  }
  expect(warn("one", HOST_TURN_MS, HOST_TURN_MS - 1)).toBe(false);
  expect(warn("suspended", HOST_TURN_MS, HOST_TURN_MS + 1)).toBe(false);
  expect(warn("next", HOST_TURN_MS, HOST_TURN_MS - TURN_WARNING_MS)).toBe(true);
});

it("does not replay skipped or muted warnings", () => {
  const warn = turnWarning();
  expect(warn("turn", HOST_TURN_MS, HOST_TURN_MS - TURN_WARNING_MS)).toBe(true); // muted
  expect(warn("turn", HOST_TURN_MS, HOST_TURN_MS - TURN_WARNING_MS + 500)).toBe(false);
  expect(warn("turn", HOST_TURN_MS, HOST_TURN_MS - 150_000)).toBe(false); // suspended
  expect(warn("turn", HOST_TURN_MS, HOST_TURN_MS - 120_000)).toBe(true);
  expect(warn("turn", HOST_TURN_MS, HOST_TURN_MS - 119_000)).toBe(false);
});

it("estimates redundancy from observed tabs rather than a fixed fleet size", () => {
  expect(hostTarget(0)).toBe(3);
  expect(hostTarget(200)).toBe(4);
  expect(hostTarget(250_000)).toBe(5_000);
});
