import "../validation.ts";
import {
  QueryClient,
  QueryClientProvider,
  skipToken,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { hostBranches, visibleBranches, type Branch, type TreeHost } from "./host-tree.ts";
import { PULSE_SECONDS, requestPulse } from "../hosting/activity.ts";
import { turnSounds, turnWarning, protectHostingTab } from "./attention.ts";
import type { HostUpdate } from "../hosting/messages.ts";
import { turnLabel } from "../policy.ts";
import { fleet } from "../fleets.ts";
import {
  AlreadyHosting,
  HostingInAnotherTab,
  HostingUnavailable,
  UploadTooSlow,
  hostTab,
  type HostState,
} from "../hosting/tab.ts";
import { readTree } from "../peers/view.ts";
import { HEARTBEAT_MS } from "../peers/presence.ts";
import { InvitationUnavailable } from "../peers/http.ts";
import { NoReachableHost, retryDelay } from "../network.ts";
import { createVisitorCheck, type Observation } from "./visitor.ts";

const labels = {
  copying: "Copying the site from another host…",
  waiting: "You've volunteered. This tab will host when needed.",
  checking: "Checking your connection…",
  starting: "Starting to host…",
  hosting: "This tab is hosting.",
  stopping: "Stopping hosting…",
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

function BranchRow({
  branch,
  now,
  self,
  depth = 0,
}: {
  branch: Branch;
  now: number;
  self: string | undefined;
  depth?: number;
}) {
  const { host, children } = branch;
  const label = host.name ?? "unnamed host";
  const former = host.left || (host.endsAt !== undefined && host.endsAt <= now);
  const state = former ? "former host" : host.unreachable ? "unreachable" : undefined;
  return (
    <li>
      <span className={state !== undefined ? "former-host" : undefined}>
        {host.runID === self ? <strong>{label} (you)</strong> : label}
        {state && <small> ({state})</small>}
      </span>
      {children.length > 0 && (
        <ul className={depth < 12 ? "host-tree" : "host-tree host-tree-deep"}>
          {children.map((child) => (
            <BranchRow
              key={child.host.runID}
              branch={child}
              now={now}
              self={self}
              depth={depth + 1}
            />
          ))}
        </ul>
      )}
    </li>
  );
}

const TREE_ROWS = 16;
const TREE_REFRESH_MS = 15_000;

function Hosts({
  origin,
  now,
  self,
  focus,
}: {
  origin: string | undefined;
  now: number;
  self: string | undefined;
  focus: string | undefined;
}) {
  const [visibleRows, setVisibleRows] = useState(TREE_ROWS);
  const [open, setOpen] = useState(false);
  const tree = useQuery({
    queryKey: ["host-tree", origin, focus],
    queryFn:
      open && origin !== undefined && focus !== undefined
        ? ({ signal }) => readTree(origin, focus, signal)
        : skipToken,
    refetchInterval: open ? TREE_REFRESH_MS : false,
    staleTime: 5_000,
    retry: (failures, error) => failures === 0 && retryDelay(error) !== undefined,
    retryDelay: (_failures, error) => retryDelay(error) ?? 0,
  });
  const roster = tree.data ?? emptyRoster;
  const branches = useMemo(() => hostBranches(roster, focus), [roster, focus]);
  const selected = useMemo(
    () => visibleBranches(branches, focus, visibleRows),
    [branches, focus, visibleRows],
  );
  if (origin === undefined || focus === undefined) return null;
  return (
    <details className="host-details" onToggle={(event) => setOpen(event.currentTarget.open)}>
      <summary>hosts</summary>
      <p className="tree-note">Follow the site from one browser to the next.</p>
      {selected.branches.some(({ host }) => host.copyFrom !== undefined) && (
        <p className="tree-note">Earlier hosts aren’t shown.</p>
      )}
      {selected.branches.length > 0 ? (
        <ul className="host-tree">
          {selected.branches.map((branch) => (
            <BranchRow key={branch.host.runID} branch={branch} now={now} self={self} />
          ))}
        </ul>
      ) : (
        <p>
          {tree.isError
            ? "Couldn't load the host report. We'll try again."
            : "Waiting for a host report."}
        </p>
      )}
      {selected.more && (
        <button
          className="text-action"
          type="button"
          onClick={() => setVisibleRows((count) => count + TREE_ROWS)}
        >
          show more
        </button>
      )}
    </details>
  );
}

const emptyRoster: readonly TreeHost[] = [];
const visitorKey = ["visitor"] as const;
const pluralRequests = (requests: number) =>
  `${requests.toLocaleString()} ${requests === 1 ? "request" : "requests"}`;

function App({ bootstrap }: { bootstrap: boolean }) {
  const [host, setHost] = useState<HostState>();
  const [lifetime, setLifetime] = useState<AbortController>();
  const [activity, setActivity] = useState<Extract<HostUpdate, { type: "activity" }>>();
  const [finished, setFinished] = useState<number>();
  const [retry, setRetry] = useState(false);
  const [message, setMessage] = useState("");
  const [alreadyHosting, setAlreadyHosting] = useState(false);
  const [now, setNow] = useState(Date.now);
  const [localStart, setLocalStart] = useState<number>();
  const [sound, setSound] = useState(true);
  const chirp = useRef<ReturnType<typeof turnSounds> | undefined>(undefined);
  const queryClient = useQueryClient();
  const [checkVisitor] = useState(createVisitorCheck);
  const visitor = useQuery({
    queryKey: visitorKey,
    queryFn: ({ signal }) => checkVisitor(signal),
    // one check already tries multiple hosts. don't replay the whole heartbeat.
    retry: false,
    refetchInterval: (query) =>
      query.state.status === "error" ? 8_000 + Math.random() * 4_000 : HEARTBEAT_MS,
    refetchIntervalInBackground: true,
    staleTime: 5_000,
  });
  const shouldWarn = useMemo(turnWarning, []);
  const label = turnLabel(bootstrap);
  const hosting = host?.type === "hosting" ? host : undefined;
  const active = hosting !== undefined;
  const observed = visitor.isSuccess && !visitor.isPaused ? visitor.data : undefined;
  const unavailable = !active && observed === null;
  const canVolunteer = observed != null;
  // query keeps the last good value when a refetch fails.
  const startedAt =
    hosting?.startedAt ?? (visitor.data === null ? null : (visitor.data?.startedAt ?? localStart));
  const ticking = typeof startedAt === "number";
  useEffect(() => {
    if (
      hosting &&
      !lifetime?.signal.aborted &&
      shouldWarn(hosting.runID, hosting.endsAt, Date.now())
    )
      chirp.current?.play("warning");
  }, [hosting, now, shouldWarn, lifetime]);
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
    if (!unavailable) return;
    setAlreadyHosting(false);
    if (!bootstrap && host?.type === "waiting") lifetime?.abort(new NoReachableHost());
  }, [unavailable, bootstrap, host, lifetime]);
  const hosts = hosting?.hosts ?? observed?.hosts ?? 0;
  const visitors = hosting?.tabs ?? observed?.tabs ?? 0;

  function closeChirp() {
    chirp.current?.close();
    chirp.current = undefined;
  }

  function toggleSound() {
    const enabled = !sound;
    setSound(enabled);
    if (!enabled) closeChirp();
    else if (lifetime !== undefined) chirp.current = turnSounds();
  }

  function start() {
    if (lifetime !== undefined || (!bootstrap && !canVolunteer)) return;
    const stop = new AbortController();
    if (sound) chirp.current = turnSounds();
    setLifetime(stop);
    setActivity(undefined);
    setFinished(undefined);
    setRetry(false);
    setMessage("");
    setAlreadyHosting(false);
    let hosted = false;
    void hostTab(
      bootstrap,
      stop.signal,
      (next) => {
        if (next.type === "checking") chirp.current?.play("invitation");
        if (next.type === "hosting") {
          hosted = true;
          setLocalStart(next.startedAt);
        }
        document.title =
          next.type === "hosting" ? "hosting · keepalive" : "can we keep this alive?";
        setHost(next);
      },
      setActivity,
    )
      .then(
        ({ expired, requests }) => {
          performance.mark("keepalive ended", { detail: expired ? "completed" : "stopped" });
          if (hosted) setFinished(requests);
          setMessage(
            expired
              ? "Your turn is over. Thanks for hosting."
              : hosted
                ? "Thanks for hosting."
                : "This tab stopped.",
          );
        },
        (error: unknown) => {
          performance.mark("keepalive ended", {
            detail: stop.signal.aborted
              ? "stopped"
              : error instanceof DOMException && error.name === "TimeoutError"
                ? "expired"
                : "failed",
          });
          if (error instanceof AlreadyHosting) {
            setAlreadyHosting(true);
            return;
          }
          if (stop.signal.reason instanceof NoReachableHost) return;
          if (error instanceof NoReachableHost) {
            void queryClient.cancelQueries({ queryKey: visitorKey }).then(() => {
              queryClient.setQueryData<Observation | null>(visitorKey, null);
            });
            return;
          }
          setRetry(!stop.signal.aborted);
          setMessage(
            stop.signal.aborted
              ? "This tab stopped."
              : error instanceof HostingInAnotherTab
                ? "Another tab in this browser profile is hosting or waiting to host."
                : error instanceof HostingUnavailable
                  ? "This tab couldn't start hosting. Try again later."
                  : error instanceof InvitationUnavailable
                    ? `${error.message} Try again.`
                    : error instanceof UploadTooSlow
                      ? "This tab couldn't complete the upload check. Try again."
                      : "This tab couldn't host the site. Try again.",
          );
        },
      )
      .finally(() => {
        closeChirp();
        document.title = "can we keep this alive?";
        setHost(undefined);
        setLifetime(undefined);
        if (hosted) void visitor.refetch();
      });
  }

  return (
    <main>
      <h1>{bootstrap ? "start keepalive" : "can we keep this alive?"}</h1>
      <p className="experiment-age">
        <span>alive for</span>
        <strong>
          {startedAt === null ? "00h 00m 00s" : startedAt === undefined ? "—" : age(startedAt, now)}
        </strong>
      </p>
      {bootstrap ? (
        <p>
          Start the first host for <a href={`https://${fleet.site}`}>{fleet.site}</a> for up to{" "}
          {label}. Keep this tab open to keep the site online.
        </p>
      ) : (
        <>
          <p>
            This site is served from people's browsers. Visitors copy it from each other and take
            15min turns keeping it online. If the last host stops, the site goes down.
          </p>
          {canVolunteer && lifetime === undefined && finished === undefined && !retry && (
            <p>Click below to volunteer, then keep this tab open. You can stop anytime.</p>
          )}
        </>
      )}
      <section aria-label="keepalive">
        <p role="status">
          {unavailable && (host === undefined || host.type === "waiting") ? (
            "No host is serving the site right now."
          ) : !canVolunteer && host?.type === "waiting" ? (
            "Checking for a host…"
          ) : host === undefined ? (
            alreadyHosting ? (
              <>
                Keepalive is already running.{" "}
                <a href={`https://${fleet.site}`}>Visit the main site</a> to volunteer.
              </>
            ) : !bootstrap && !canVolunteer ? (
              "Checking for a host…"
            ) : (
              message || "You can help keep it online."
            )
          ) : host.type === "copying" && host.bootstrap ? (
            "Copying the site to this tab…"
          ) : (
            labels[host.type]
          )}
        </p>
        {host?.type === "copying" && <CopyProgress received={host.received} total={host.total} />}
        {hosting && (
          <>
            <p className="turn-countdown">
              {countdown(hosting.endsAt, Math.max(now, hosting.since))} left in your turn
            </p>
            <div className="host-activity">
              <div>
                serving ~{hosting.localTabs.toLocaleString()} of ~{hosting.tabs.toLocaleString()}{" "}
                {hosting.tabs === 1 ? "tab" : "tabs"}
              </div>
              <div className="request-line">
                <span className="request-pulse" aria-hidden="true">
                  {activity
                    ? requestPulse(activity.pulse, activity.second, now)
                    : "_".repeat(PULSE_SECONDS)}
                </span>
                <span>{pluralRequests(activity?.requests ?? 0)}</span>
              </div>
            </div>
          </>
        )}
        {finished !== undefined && (
          <>
            <p>
              {bootstrap || canVolunteer
                ? `You can close this tab or ${bootstrap ? "host" : "volunteer"} again.`
                : "You can close this tab."}
            </p>
            <p>{pluralRequests(finished)} handled</p>
          </>
        )}
        <p>
          {unavailable
            ? "0 reachable hosts"
            : hosts === 0
              ? "— tabs · — hosts"
              : `~${visitors.toLocaleString()} ${visitors === 1 ? "tab" : "tabs"} · ${hosts.toLocaleString()} ${hosts === 1 ? "host" : "hosts"}`}
        </p>
        {(hosting?.saturated ?? observed?.saturated) && <p>Some hosts aren’t shown.</p>}
        <Hosts
          key={hosting?.runID}
          origin={hosting?.origin ?? observed?.host.origin}
          now={now}
          self={hosting?.runID}
          focus={hosting?.runID ?? observed?.host.runID}
        />
      </section>
      <div className="actions">
        {alreadyHosting ? null : lifetime === undefined ? (
          (bootstrap || canVolunteer) && (
            <button type="button" onClick={start}>
              {retry
                ? "try again"
                : finished !== undefined
                  ? bootstrap
                    ? "host again"
                    : "volunteer again"
                  : bootstrap
                    ? "start hosting"
                    : "i'll keep it alive"}
            </button>
          )
        ) : (
          <button
            type="button"
            onClick={() => lifetime.abort()}
            disabled={host?.type === "stopping"}
          >
            stop
          </button>
        )}
        {lifetime !== undefined && (
          <button
            className="text-action"
            type="button"
            onClick={toggleSound}
            aria-pressed={sound}
            title="Play an invitation sound in the background and a warning each minute in the final five minutes"
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
      className="copy-progress"
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
if (root !== null)
  createRoot(root).render(
    <QueryClientProvider client={new QueryClient()}>
      <App bootstrap={root.hasAttribute("data-start")} />
    </QueryClientProvider>,
  );
