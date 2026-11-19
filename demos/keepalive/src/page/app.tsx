import "../validation.ts";
import { render } from "preact";
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { hostBranches, type TreeHost } from "./host-tree.ts";
import { PULSE_SECONDS, requestPulse } from "../hosting/activity.ts";
import { invitationChirp, protectHostingTab, saveSound, soundEnabled } from "./attention.ts";
import type { HostUpdate } from "../hosting/messages.ts";
import { turnLabel } from "../policy.ts";
import { HostingUnavailable, UploadTooSlow, hostTab, type HostState } from "../hosting/tab.ts";
import { reportedTabs } from "../peers/gossip.ts";
import { observeVisitors, type Observation } from "./visitor.ts";

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
  const seconds = Math.floor(Math.max(0, now - since) / 1_000);
  const part = (value: number) => String(value).padStart(2, "0");
  const days = Math.floor(seconds / 86_400);
  const clock = `${part(Math.floor(seconds / 3_600) % 24)}h ${part(Math.floor(seconds / 60) % 60)}m ${part(seconds % 60)}s`;
  return days > 0 ? `${days}d ${clock}` : clock;
}

type Branch = ReturnType<typeof hostBranches>[number]["root"];

function BranchRow({
  branch,
  now,
  self,
  prefix = "",
  edge = "",
  next = "",
}: {
  branch: Branch;
  now: number;
  self: string | undefined;
  prefix?: string;
  edge?: string;
  next?: string;
}) {
  const { host, children } = branch;
  const label = host.name ?? "unnamed host";
  const former = host.left || (host.endsAt !== undefined && host.endsAt <= now);
  return (
    <li>
      <span class="tree-edge" aria-hidden="true">
        {prefix}
        {edge}
      </span>
      <span class={former ? "former-host" : undefined}>
        {host.runID === self ? <strong>{label} (you)</strong> : label}
        {former && <span class="visually-hidden"> (former host)</span>}
      </span>
      {children.length > 0 && (
        <ul class="host-tree">
          {children.map((child, index) => (
            <BranchRow
              key={child.host.runID}
              branch={child}
              now={now}
              self={self}
              prefix={prefix + next}
              edge="+-- "
              next={index === children.length - 1 ? "    " : "|   "}
            />
          ))}
        </ul>
      )}
    </li>
  );
}

function Hosts({
  roster,
  now,
  self,
  focus,
}: {
  roster: readonly TreeHost[];
  now: number;
  self: string | undefined;
  focus: string | undefined;
}) {
  const [anchor, setAnchor] = useState<string>();
  const pages = useMemo(() => hostBranches(roster, focus), [roster, focus]);
  const index = Math.max(
    0,
    pages.findIndex((page) => page.focusID === anchor),
  );
  const page = pages[index];
  if (page === undefined) return null;
  return (
    <details class="host-details">
      <summary>hosts</summary>
      <p class="tree-note">how it spread</p>
      {page.continued && <div aria-label="Earlier hosts not shown">...</div>}
      <ul class="host-tree">
        <BranchRow branch={page.root} now={now} self={self} />
      </ul>
      {pages.length > 1 && (
        <button
          class="text-action"
          type="button"
          onClick={() => setAnchor(pages[index + 1]?.focusID)}
        >
          {index === pages.length - 1 ? "back to first branch" : "show more"}
        </button>
      )}
    </details>
  );
}

const emptyRoster: readonly TreeHost[] = [];
const pluralRequests = (requests: number) =>
  `${requests.toLocaleString()} ${requests === 1 ? "request" : "requests"}`;

function App({ bootstrap }: { bootstrap: boolean }) {
  const [host, setHost] = useState<HostState>();
  const [lifetime, setLifetime] = useState<AbortController>();
  const [activity, setActivity] = useState<Extract<HostUpdate, { type: "activity" }>>();
  const [finished, setFinished] = useState<number>();
  const [message, setMessage] = useState("");
  const [now, setNow] = useState(Date.now);
  const [observed, setObserved] = useState<Observation>();
  const [lastStart, setLastStart] = useState<number>();
  const [sound, setSound] = useState(soundEnabled);
  const chirp = useRef<ReturnType<typeof invitationChirp>>(undefined);
  const label = turnLabel(bootstrap);
  const hosting = host?.type === "hosting" ? host : undefined;
  const startedAt = hosting?.startedAt ?? observed?.startedAt ?? lastStart;
  const ticking = startedAt !== undefined || hosting !== undefined;
  const active = hosting !== undefined;
  useEffect(() => {
    if (!ticking) return;
    const timer = setInterval(() => setNow(Date.now()), 1_000);
    setNow(Date.now());
    return () => clearInterval(timer);
  }, [ticking]);
  useEffect(() => {
    if (active) return protectHostingTab();
    return undefined;
  }, [active]);
  useEffect(() => {
    const lifetime = new AbortController();
    void observeVisitors(lifetime.signal, (next) => {
      setObserved(next);
      if (next !== undefined) setLastStart(next.startedAt);
    });
    return () => lifetime.abort();
  }, []);
  const roster = hosting?.roster ?? observed?.roster ?? emptyRoster;
  const hosts =
    hosting?.hosts ?? roster.filter((peer) => !peer.left && (peer.endsAt ?? Infinity) > now).length;
  const visitors = hosting?.tabs ?? reportedTabs(observed?.roster ?? [], now);

  function closeChirp() {
    chirp.current?.close();
    chirp.current = undefined;
  }

  function toggleSound() {
    const enabled = !sound;
    setSound(enabled);
    saveSound(enabled);
    if (!enabled) closeChirp();
    else if (host?.type === "waiting") chirp.current = invitationChirp();
  }

  function start() {
    if (lifetime !== undefined) return;
    const stop = new AbortController();
    if (sound && !bootstrap) chirp.current = invitationChirp();
    setLifetime(stop);
    setActivity(undefined);
    setFinished(undefined);
    setMessage("");
    let hosted = false;
    void hostTab(
      bootstrap,
      stop.signal,
      (next) => {
        if (next.type === "checking") chirp.current?.play();
        if (next.type === "hosting") {
          hosted = true;
          setLastStart(next.startedAt);
          closeChirp();
        }
        document.title =
          next.type === "hosting" ? "hosting · keepalive" : "can we keep this alive?";
        setHost(next);
      },
      setActivity,
    )
      .then(
        ({ expired, requests }) => {
          if (hosted) setFinished(requests);
          setMessage(
            expired
              ? "Your turn is over. Thanks for hosting."
              : hosted
                ? "Thanks for hosting."
                : "This tab stopped.",
          );
        },
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
        closeChirp();
        document.title = "can we keep this alive?";
        setHost(undefined);
        setLifetime(undefined);
      });
  }

  return (
    <main>
      <h1>{bootstrap ? "start keepalive" : "can we keep this alive?"}</h1>
      <p class="experiment-age">
        <span>alive for</span>
        <strong>{startedAt === undefined ? "—" : age(startedAt, now)}</strong>
      </p>
      {bootstrap ? (
        <p>
          Start a browser host for <a href="https://keepthisalive.com">keepthisalive.com</a>. Keep
          this tab open to serve the site. A bootstrap turn lasts up to {label}.
        </p>
      ) : (
        <>
          <p>This site is served from people's browsers.</p>
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
        {hosting && (
          <>
            <p>{countdown(hosting.endsAt, Math.max(now, hosting.since))} left in your turn</p>
            <div class="host-activity">
              <div>
                {hosting.localTabs.toLocaleString()} / ~{hosting.tabs.toLocaleString()} tabs
              </div>
              <div class="request-line">
                <span class="request-pulse" aria-hidden="true">
                  {activity
                    ? requestPulse(activity.pulse, activity.second, now)
                    : "_".repeat(PULSE_SECONDS)}
                </span>
                <span>{pluralRequests(activity?.requests ?? 0)}</span>
              </div>
            </div>
          </>
        )}
        {finished !== undefined && <p>{pluralRequests(finished)} handled</p>}
        {!hosting && hosts > 0 && (
          <p>
            ~{visitors} {visitors === 1 ? "tab" : "tabs"} · {hosts} {hosts === 1 ? "host" : "hosts"}
          </p>
        )}
        <Hosts
          key={hosting?.runID}
          roster={roster}
          now={now}
          self={hosting?.runID}
          focus={hosting?.runID ?? observed?.hostRunID}
        />
      </section>
      <div class="actions">
        {lifetime === undefined ? (
          <button type="button" onClick={start}>
            {bootstrap ? "start hosting" : "i'll keep it alive"}
          </button>
        ) : (
          <button
            type="button"
            onClick={() => lifetime.abort()}
            disabled={host?.type === "stopping"}
          >
            stop
          </button>
        )}
        {host?.type === "waiting" && (
          <button
            class="text-action"
            type="button"
            onClick={toggleSound}
            title="Play a short sound if this tab is chosen in the background"
          >
            sound: {sound ? "on" : "off"}
          </button>
        )}
      </div>
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
