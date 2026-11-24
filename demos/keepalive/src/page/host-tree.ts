import type { HostHistory } from "../peers/gossip.ts";

export type TreeHost = HostHistory;
export type Branch = { host: TreeHost; children: Branch[] };

export function hostBranches(roster: readonly TreeHost[], focusID: string | undefined) {
  const hosts = new Map<string, Branch>(roster.map((host) => [host.runID, { host, children: [] }]));
  const parent = new Map<string, string>();
  for (const [id, branch] of hosts) {
    const source = branch.host.copyFrom;
    // keep only known, acyclic links. every accepted link is reported by its child.
    if (source === undefined) continue;
    const donor = hosts.get(source);
    if (donor === undefined) continue;
    let ancestor: string | undefined = source;
    while (ancestor !== undefined && ancestor !== id) ancestor = parent.get(ancestor);
    if (ancestor === id) continue;
    parent.set(id, source);
    donor.children.push(branch);
  }

  // prioritize the full handoff leading to this host, not the order of random run IDs.
  let focusRoot = focusID;
  for (let root = focusRoot && parent.get(focusRoot); root; root = parent.get(root)) {
    focusRoot = root;
  }
  const roots = [...hosts.values()].filter(({ host }) => !parent.has(host.runID));
  const focused = roots.findIndex(({ host }) => host.runID === focusRoot);
  if (focused > 0) roots.unshift(...roots.splice(focused, 1));
  return roots;
}

export function visibleBranches(
  roots: readonly Branch[],
  focusID: string | undefined,
  limit: number,
) {
  const selected = new Set<Branch>();
  function includePath(branch: Branch): boolean {
    if (branch.host.runID === focusID) {
      for (const child of branch.children.slice(0, 4)) selected.add(child);
    } else if (!branch.children.some(includePath)) return false;
    selected.add(branch);
    return true;
  }
  if (focusID !== undefined) roots.some(includePath);

  // always show the path to the current host. spend the remaining rows on
  // nearby branches first, and keep them in place when more rows are revealed.
  const queue = [...roots];
  for (let i = 0; i < queue.length && selected.size < limit; i++) {
    const branch = queue[i];
    if (branch === undefined) continue;
    selected.add(branch);
    queue.push(...branch.children);
  }
  let more = false;
  function visible(branches: readonly Branch[]): Branch[] {
    return branches.flatMap((branch) => {
      if (!selected.has(branch)) {
        more = true;
        return [];
      }
      return [{ host: branch.host, children: visible(branch.children) }];
    });
  }
  return { branches: visible(roots), more };
}
