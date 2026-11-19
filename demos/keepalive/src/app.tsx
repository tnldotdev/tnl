import "./validation.ts";
import { render } from "preact";
import { useEffect, useState } from "preact/hooks";
import { turnLabel } from "./hosting/policy.ts";
import { HostingUnavailable, UploadTooSlow, hostTab, type HostState } from "./hosting/tab.ts";
import { reportedTabs, type Change } from "./peers.ts";
import { observeVisitors } from "./visitor.ts";

const labels = {
  copying: "Downloading files to serve visitors…",
  waiting: "Waiting to host…",
  checking: "Checking your upload…",
  starting: "Starting to host…",
  hosting: "This tab is hosting.",
  stopping: "Stopping…",
} as const;

function countdown(endsAt: number, now: number) {
  const seconds = Math.max(0, Math.ceil((endsAt - now) / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

function age(since: number, now: number) {
  const minutes = Math.floor(Math.max(0, now - since) / 60_000);
  if (minutes < 1) return "less than a minute";
  if (minutes < 60) return `${minutes}m`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

type RosterEntry = Pick<
  Change,
  | "runID"
  | "name"
  | "left"
  | "endsAt"
  | "departing"
  | "startingUntil"
  | "copyFrom"
  | "invitedBy"
  | "replacedBy"
>;

function rosterLabels(roster: readonly RosterEntry[], self?: string) {
  return new Map(
    roster.map(({ name, runID }) => [
      runID,
      runID === self
        ? `${name ?? "this tab"} (you)`
        : name && roster.some((peer) => peer.name === name && peer.runID !== runID)
          ? `${name}-${runID.slice(-4)}`
          : (name ?? "unnamed host"),
    ]),
  );
}

function HostRoster({
  roster,
  now,
  self,
  files,
  startedAt,
}: {
  roster: readonly RosterEntry[];
  now: number;
  self: string | undefined;
  files: number | undefined;
  startedAt: number | undefined;
}) {
  const names = rosterLabels(roster, self);
  const live = roster.filter((peer) => !peer.left && (peer.endsAt ?? Infinity) > now);
  const edges = roster
    .flatMap((peer) => [
      ...(peer.copyFrom && names.has(peer.copyFrom)
        ? [{ from: peer.copyFrom, to: peer.runID, kind: "shared a copy" }]
        : []),
      ...(peer.invitedBy && peer.invitedBy !== peer.copyFrom && names.has(peer.invitedBy)
        ? [{ from: peer.invitedBy, to: peer.runID, kind: "invited" }]
        : []),
      ...(peer.replacedBy && names.has(peer.replacedBy)
        ? [{ from: peer.runID, to: peer.replacedBy, kind: "handed off" }]
        : []),
    ])
    .slice(-12);
  if (live.length === 0) return null;
  return (
    <details class="host-details">
      <summary>hosts and handoffs</summary>
      <ul class="host-roster">
        {live.slice(0, 12).map((peer) => (
          <li key={peer.runID}>
            <span aria-hidden="true">+- </span>
            {names.get(peer.runID)} · {peer.departing ? "leaving" : "hosting"}
            {peer.endsAt === undefined ? "" : ` · ${countdown(peer.endsAt, now)}`}
            {peer.startingUntil > now && " · inviting"}
          </li>
        ))}
      </ul>
      {edges.length > 0 && (
        <ul class="host-roster">
          {edges.map(({ from, to, kind }) => (
            <li key={`${from}:${to}:${kind}`}>
              {names.get(from)} <span aria-hidden="true">--&gt;</span> {names.get(to)}
              {" · "}
              {kind}
            </li>
          ))}
        </ul>
      )}
      {files !== undefined && <p>{files} files served by this tab</p>}
      {startedAt !== undefined && <p>experiment age: {age(startedAt, now)}</p>}
    </details>
  );
}

function App({ bootstrap }: { bootstrap: boolean }) {
  const [host, setHost] = useState<HostState>();
  const [lifetime, setLifetime] = useState<{ stop: AbortController; replace: AbortController }>();
  const [replacing, setReplacing] = useState(false);
  const [message, setMessage] = useState("");
  const [now, setNow] = useState(Date.now);
  const [observed, setObserved] = useState<Change[]>([]);
  const label = turnLabel(bootstrap);
  const endsAt = host?.type === "hosting" ? host.endsAt : undefined;
  useEffect(() => {
    if (endsAt === undefined && observed.length === 0) return;
    const timer = setInterval(() => setNow(Date.now()), 1_000);
    setNow(Date.now());
    return () => clearInterval(timer);
  }, [endsAt, observed.length === 0]);
  useEffect(() => {
    const lifetime = new AbortController();
    void observeVisitors(lifetime.signal, setObserved);
    return () => lifetime.abort();
  }, []);
  const hosting = host?.type === "hosting" ? host : undefined;
  const roster = hosting?.roster ?? observed;
  const hosts =
    hosting?.hosts ??
    observed.filter((peer) => !peer.left && (peer.endsAt ?? Infinity) > now).length;
  const visitors = hosting?.tabs ?? reportedTabs(observed, now);
  const copyFrom = roster.find((peer) => peer.runID === hosting?.runID)?.copyFrom;
  const copyName = copyFrom && rosterLabels(roster).get(copyFrom);

  function start() {
    if (lifetime !== undefined) return;
    const stop = new AbortController();
    const replace = new AbortController();
    const close = (event: BeforeUnloadEvent) => event.preventDefault();
    window.addEventListener("beforeunload", close);
    setLifetime({ stop, replace });
    setReplacing(false);
    setMessage("");
    void hostTab(bootstrap, stop.signal, replace.signal, (next) => {
      document.title = next.type === "hosting" ? "hosting · keepalive" : "can we keep this alive?";
      setHost(next);
    })
      .then(
        ({ expired, replacement }) =>
          setMessage(
            replacement
              ? `${replacement} is serving now. Thanks for hosting.`
              : expired
                ? `Your turn is over (${label}).`
                : "This tab stopped hosting.",
          ),
        (error: unknown) =>
          setMessage(
            stop.signal.aborted
              ? "This tab stopped."
              : error instanceof HostingUnavailable
                ? "Hosting isn't available right now. Try again later."
                : error instanceof UploadTooSlow
                  ? "This connection isn't fast enough to host right now."
                  : "This tab couldn't host the site. Try again.",
          ),
      )
      .finally(() => {
        window.removeEventListener("beforeunload", close);
        document.title = "can we keep this alive?";
        setHost(undefined);
        setLifetime(undefined);
      });
  }

  return (
    <main>
      <h1>{bootstrap ? "start keepalive" : "can we keep this alive?"}</h1>
      {bootstrap ? (
        <p>
          Start a browser host for <a href="https://keepthisalive.com">keepthisalive.com</a>. Keep
          this tab open to serve the site. A bootstrap turn lasts up to {label}.
        </p>
      ) : (
        <>
          <p>This site runs in people's browsers.</p>
          <p>
            Keep this tab open and it'll host when needed, for up to {label}. You can stop anytime.
          </p>
        </>
      )}
      <section aria-label="keepalive">
        <p role="status">
          {host === undefined ? message || "You can help keep it online." : labels[host.type]}
        </p>
        {host?.type === "copying" && <CopyProgress received={host.received} total={host.total} />}
        {hosting && <p>{countdown(hosting.endsAt, Math.max(now, hosting.since))} remaining</p>}
        {hosts > 0 && (
          <p>
            about {visitors} {visitors === 1 ? "tab" : "tabs"} · {hosts}{" "}
            {hosts === 1 ? "host" : "hosts"} recently seen
          </p>
        )}
        {copyName && <p>your copy came from {copyName}</p>}
        <HostRoster
          roster={roster}
          now={now}
          self={hosting?.runID}
          files={hosting?.filesServed}
          startedAt={hosting?.startedAt}
        />
      </section>
      {lifetime === undefined ? (
        <button type="button" onClick={start}>
          {bootstrap ? "start hosting" : "i'll keep it alive"}
        </button>
      ) : (
        <>
          {host?.type === "hosting" && (
            <button
              type="button"
              disabled={replacing || host.replacing}
              onClick={() => {
                setReplacing(true);
                lifetime.replace.abort();
              }}
            >
              {replacing || host.replacing ? "looking for another host…" : "find my replacement"}
            </button>
          )}
          <button
            type="button"
            onClick={() => lifetime.stop.abort()}
            disabled={host?.type === "stopping"}
          >
            stop
          </button>
        </>
      )}
      <footer>
        an experiment from <a href="https://tnl.dev">tnl.dev</a> ·{" "}
        <a href="https://tnl.dev/blog/keepalive">how it works</a> ·{" "}
        <a href="https://github.com/tnldotdev/tnl/tree/main/demos/keepalive">source</a>
      </footer>
    </main>
  );
}

function CopyProgress({ received, total }: { received: number; total: number }) {
  const filled = Math.floor((received / total) * 20);
  const mb = (bytes: number) => (bytes / 1_000_000).toFixed(1);
  return (
    <p
      class="copy-progress"
      role="progressbar"
      aria-label="Downloading hosting files"
      aria-valuemin={0}
      aria-valuemax={total}
      aria-valuenow={received}
    >
      <span aria-hidden="true">
        [{"#".repeat(filled)}
        {"-".repeat(20 - filled)}]
      </span>{" "}
      {mb(received)} / {mb(total)} MB
    </p>
  );
}

const root = document.getElementById("app");
if (root !== null) render(<App bootstrap={root.hasAttribute("data-start")} />, root);
