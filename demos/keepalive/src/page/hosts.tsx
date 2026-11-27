import { useQuery } from "@tanstack/solid-query";
import { createMemo, createSignal, For, Show } from "solid-js";
import { readTree } from "../peers/view.ts";
import { retryDelay } from "../network.ts";
import { hostBranches, visibleBranches, type Branch, type TreeHost } from "./host-tree.ts";

function BranchRow(props: {
  branch: Branch;
  now: number;
  self: string | undefined;
  depth: number;
}) {
  const host = () => props.branch.host;
  const label = () => host().name ?? "unnamed host";
  const state = () =>
    host().left || (host().endsAt ?? Infinity) <= props.now
      ? "former host"
      : host().unreachable
        ? "unreachable"
        : undefined;
  return (
    <li>
      <span class={state() ? "former-host" : undefined}>
        <Show when={host().runID === props.self} fallback={label()}>
          <strong>{label()} (you)</strong>
        </Show>
        <Show when={state()}>{(value) => <small> ({value()})</small>}</Show>
      </span>
      <Show when={props.branch.children.length > 0}>
        <ul class={props.depth < 12 ? "host-tree" : "host-tree host-tree-deep"}>
          <For each={props.branch.children}>
            {(child) => (
              <BranchRow branch={child} now={props.now} self={props.self} depth={props.depth + 1} />
            )}
          </For>
        </ul>
      </Show>
    </li>
  );
}

const emptyRoster: readonly TreeHost[] = [];
const TREE_ROWS = 16;
export default function Hosts(props: {
  origin: string;
  now: number;
  self: string | undefined;
  focus: string;
}) {
  const [visibleRows, setVisibleRows] = createSignal(TREE_ROWS);
  const tree = useQuery(() => {
    const origin = props.origin;
    const focus = props.focus;
    return {
      queryKey: ["host-tree", origin, focus],
      queryFn: ({ signal }) => readTree(origin, focus, signal),
      refetchInterval: 15_000,
      staleTime: 5_000,
      throwOnError: false,
      retry: (failures, error) => failures === 0 && retryDelay(error) !== undefined,
      retryDelay: (_failures, error) => retryDelay(error) ?? 0,
    };
  });
  const branches = createMemo(() => hostBranches(tree.data ?? emptyRoster, props.focus));
  const selected = createMemo(() => visibleBranches(branches(), props.focus, visibleRows()));
  return (
    <>
      <p class="tree-note">Follow the site from one browser to the next.</p>
      <Show when={selected().branches.some(({ host }) => host.copyFrom !== undefined)}>
        <p class="tree-note">Earlier hosts aren’t shown.</p>
      </Show>
      <Show
        when={selected().branches.length > 0}
        fallback={
          <p>
            {tree.isError
              ? "Couldn't load the host report. We'll try again."
              : "Waiting for a host report."}
          </p>
        }
      >
        <ul class="host-tree">
          <For each={selected().branches}>
            {(branch) => <BranchRow branch={branch} now={props.now} self={props.self} depth={0} />}
          </For>
        </ul>
      </Show>
      <Show when={selected().more}>
        <button
          class="text-action"
          type="button"
          onClick={() => setVisibleRows((count) => count + TREE_ROWS)}
        >
          show more
        </button>
      </Show>
    </>
  );
}
