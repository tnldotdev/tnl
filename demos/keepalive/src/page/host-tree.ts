import type { Change } from "../peers/gossip.ts";

export type TreeHost = Pick<Change, "runID" | "name" | "copyFrom" | "left" | "endsAt">;
type Branch = { host: TreeHost; children: Branch[] };

export function hostBranches(roster: readonly TreeHost[], focusID: string | undefined) {
  const hosts = new Map(roster.map((host) => [host.runID, host]));
  const ids = [...hosts.keys()].sort();
  const parent = new Map<string, string>();
  const children = new Map<string, string[]>();
  for (const id of ids) {
    const source = hosts.get(id)?.copyFrom;
    // keep only known, acyclic links. every accepted link is reported by its child.
    if (source === undefined || !hosts.has(source)) continue;
    let ancestor: string | undefined = source;
    while (ancestor !== undefined && ancestor !== id) ancestor = parent.get(ancestor);
    if (ancestor === id) continue;
    parent.set(id, source);
    const siblings = children.get(source) ?? [];
    siblings.push(id);
    children.set(source, siblings);
  }

  const covered = new Set<string>();
  const pages: { focusID: string; root: Branch; continued: boolean }[] = [];
  const order = focusID === undefined ? ids : [focusID, ...ids];
  for (const focus of order) {
    if (covered.has(focus) || !hosts.has(focus)) continue;
    const rootID = parent.get(focus) ?? focus;
    const rootHost = hosts.get(rootID);
    if (rootHost === undefined) continue;
    const root: Branch = { host: rootHost, children: [] };
    const added = new Map([[rootID, root]]);
    covered.add(rootID);
    function add(id: string, branch: Branch) {
      if (added.size >= 8 || added.has(id)) return undefined;
      const host = hosts.get(id);
      if (host === undefined) return undefined;
      const child: Branch = { host, children: [] };
      added.set(id, child);
      covered.add(id);
      branch.children.push(child);
      return child;
    }
    const freshChildren = (id: string) =>
      (children.get(id) ?? []).filter((child) => !covered.has(child));
    const focused = focus === rootID ? root : add(focus, root);
    if (focused !== undefined) for (const child of freshChildren(focus)) add(child, focused);
    if (focus !== rootID) for (const sibling of freshChildren(rootID)) add(sibling, root);
    for (const branch of root.children)
      for (const child of freshChildren(branch.host.runID)) add(child, branch);
    pages.push({ focusID: focus, root, continued: rootHost.copyFrom !== undefined });
  }
  return pages;
}
