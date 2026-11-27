import { expect, it } from "vitest";
import { capacityTarget, recruitmentDeficit } from "./recruitment.ts";
import { hostTarget } from "../src/policy.ts";

const target = (readerBytesPerSecond: number, countedReaderLeases: number) =>
  capacityTarget({
    readerBytesPerSecond,
    countedReaderLeases,
    // a fixture budget, not a product default or a measured serving capacity.
    safeBytesPerSecondPerHost: 100_000,
  });

it("keeps a redundancy floor and independently budgets delivery and reader tracking", () => {
  expect(target(0, 0)).toBe(3);
  expect(target(1_000_000, 50)).toBe(10);
  expect(target(0, 25_000)).toBe(98);
  expect(target(0, 6_250)).toBe(25);
  expect(target(0, 769)).toBe(4);
});

it("does not recruit 500 hosts just because 25000 quiet readers are present", () => {
  expect(hostTarget(25_000)).toBe(500);
  expect(target(100_000, 25_000)).toBe(98);
});

it("counts starting replacements once and does not count departing capacity as durable", () => {
  expect(recruitmentDeficit({ needed: 10, readyBeyondReplacementWindow: 7, starting: 2 })).toBe(1);
  expect(recruitmentDeficit({ needed: 3, readyBeyondReplacementWindow: 4, starting: 2 })).toBe(0);
});

it("rejects missing demand instead of treating it as zero", () => {
  expect(() => target(Number.NaN, 10)).toThrow();
  expect(() => target(10, Number.NaN)).toThrow();
  expect(() =>
    capacityTarget({
      readerBytesPerSecond: 1,
      countedReaderLeases: 1,
      safeBytesPerSecondPerHost: 0,
    }),
  ).toThrow();
});
