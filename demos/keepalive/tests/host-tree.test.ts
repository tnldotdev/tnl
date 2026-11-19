import { expect, it } from "vitest";
import { hostBranches, type TreeHost } from "../src/page/host-tree.ts";

const host = (runID: string, copyFrom?: string): TreeHost => ({
  runID,
  copyFrom,
  name: "quiet-pine",
  left: runID === "root",
});
type Branch = ReturnType<typeof hostBranches>[number]["root"];
function rows(branch: Branch, depth = 1): { host: TreeHost; depth: number }[] {
  return [
    { host: branch.host, depth },
    ...branch.children.flatMap((child) => rows(child, depth + 1)),
  ];
}

it("shows bounded slices centered on the chosen host without losing identical names", () => {
  const descendants = Array.from({ length: 15 }, (_, n) => host(`child-${n}`, "me"));
  const roster = [
    host("root"),
    host("me", "root"),
    host("sibling", "root"),
    host("grandchild", "child-0"),
    ...descendants,
  ];
  const pages = hostBranches(roster, "me");
  expect(pages[0]?.root.host.runID).toBe("root");
  expect(pages[0]?.root.children[0]?.host.runID).toBe("me");
  for (const { root } of pages) {
    const slice = rows(root);
    expect(slice.length).toBeLessThanOrEqual(8);
    expect(slice.every(({ depth }) => depth <= 3)).toBe(true);
    expect(new Set(slice.map(({ host }) => host.runID)).size).toBe(slice.length);
  }
  expect(new Set(pages.flatMap(({ root }) => rows(root).map(({ host }) => host.runID))).size).toBe(
    roster.length,
  );
  expect(hostBranches(roster.toReversed(), "me")).toEqual(pages);
});

it("marks missing and cyclic links as incomplete rather than making up an ancestor", () => {
  const pages = hostBranches([host("a", "b"), host("b", "a"), host("c", "unknown")], "a");
  expect(pages).toHaveLength(2);
  expect(pages.every(({ continued }) => continued)).toBe(true);
  expect(pages[0]?.root.children[0]?.host.runID).toBe("a");
  expect(pages[1]?.root.children).toEqual([]);
});
