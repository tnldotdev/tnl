import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { expect, onTestFinished, test } from "vitest";
import { requestTunnelAssignment, type TnlWorktree } from "./dist/index.js";
import { startTestBootstrap } from "./test-helper.js";

test("uses the Git worktree root for a nested directory", async () => {
  const worktree = await observeWorktree(path.join(process.cwd(), "packages", "dev", "src"));
  const root = process.cwd();

  expect(worktree).toEqual({
    isGit: true,
    label: expectedLabel(path.basename(root), root),
    name: path.basename(root),
    root,
  });
});

test.each([
  ["normalizes readable names", "Cafe\u0301 Feature___Auth", "cafe-feature-auth"],
  ["falls back for punctuation", "---___", "worktree"],
  ["limits long names", "A".repeat(70), "a".repeat(56)],
])("%s", async (_description, name, stem) => {
  const directory = await temporaryDirectory(name);
  const worktree = await observeWorktree(directory);

  expect(worktree).toEqual({
    isGit: false,
    label: expectedLabel(stem, directory),
    name,
    root: directory,
  });
  expect(worktree.label.length).toBeLessThanOrEqual(63);
});

test("distinguishes same-named directories by their roots", async () => {
  const first = await temporaryDirectory("feature-auth");
  const second = await temporaryDirectory("feature-auth");

  const firstWorktree = await observeWorktree(first);
  const secondWorktree = await observeWorktree(second);

  expect(firstWorktree.label).toBe(expectedLabel("feature-auth", first));
  expect(secondWorktree.label).toBe(expectedLabel("feature-auth", second));
  expect(firstWorktree.label).not.toBe(secondWorktree.label);
});

async function observeWorktree(cwd: string): Promise<TnlWorktree> {
  const bootstrap = await startTestBootstrap();
  onTestFinished(() => bootstrap.close());
  const observed: TnlWorktree[] = [];
  await requestTunnelAssignment(
    {
      framework: "vite",
      options: ({ worktree }) => {
        observed.push(worktree);
        return {};
      },
    },
    bootstrap.environment,
    cwd,
  );
  const worktree = observed[0];
  if (worktree === undefined) {
    throw new Error("tnl options factory did not receive worktree context");
  }
  return worktree;
}

async function temporaryDirectory(name: string): Promise<string> {
  const parent = await mkdtemp(path.join(tmpdir(), "tnl-worktree-test-"));
  onTestFinished(() => rm(parent, { force: true, recursive: true }));
  const directory = path.join(parent, name);
  await mkdir(directory);
  return directory;
}

function expectedLabel(stem: string, root: string): string {
  const suffix = createHash("sha256").update(root).digest("hex").slice(0, 6);
  return `${stem}-${suffix}`;
}
