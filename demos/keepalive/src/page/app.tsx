import "../validation.ts";
import { QueryClient, QueryClientProvider, useQuery, useQueryClient } from "@tanstack/solid-query";
import {
  batch,
  createEffect,
  createMemo,
  createSignal,
  ErrorBoundary,
  lazy,
  onCleanup,
  Show,
  Suspense,
} from "solid-js";
import { render } from "solid-js/web";
import type { HostUpdate } from "../hosting/messages.ts";
import type { HostState } from "../hosting/tab.ts";
import { HEARTBEAT_MS } from "../peers/presence.ts";
import { fleet } from "../fleets.ts";
import { NoReachableHost } from "../network.ts";
import { turnSounds, turnWarning, protectHostingTab } from "./attention.ts";
import { createVisitorCheck, type Observation } from "./visitor.ts";

const visitorKey = ["visitor"] as const;
const labels = {
  copying: "Copying the site from another host…",
  waiting: "You've volunteered. This tab will host when needed.",
  checking: "Checking your connection…",
  starting: "Starting to host…",
  hosting: "This tab is hosting.",
  stopping: "Stopping hosting…",
} as const;
const pluralRequests = (requests: number) =>
  `${requests.toLocaleString()} ${requests === 1 ? "request" : "requests"}`;

const TurnView = lazy(() => import("./turn.tsx"));

function loadTurn(signal: AbortSignal) {
  signal.throwIfAborted();
  return new Promise<typeof import("./turn.tsx")>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    // imports cannot be canceled, but a late module must never start a turn.
    void import("./turn.tsx").then(
      (module) => {
        signal.removeEventListener("abort", abort);
        resolve(module);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", abort);
        reject(error);
      },
    );
  });
}

function age(since: number, now: number) {
  const seconds = Math.floor(Math.max(0, now - since) / 1_000);
  const part = (value: number) => String(value).padStart(2, "0");
  const days = Math.floor(seconds / 86_400);
  const clock = `${part(Math.floor(seconds / 3_600) % 24)}h ${part(Math.floor(seconds / 60) % 60)}m ${part(seconds % 60)}s`;
  return days > 0 ? `${days}d ${clock}` : clock;
}

function HostPanel(props: {
  origin: string;
  focus: string;
  self: string | undefined;
  now: number;
}) {
  // a new expansion can retry a failed chunk; errors stay inside this feature.
  const Hosts = lazy(() => import("./hosts.tsx"));
  return (
    <ErrorBoundary
      fallback={<p>Couldn't load the host report. Close and reopen hosts to try again.</p>}
    >
      <Suspense fallback={<p>Loading the host report…</p>}>
        <Hosts origin={props.origin} focus={props.focus} self={props.self} now={props.now} />
      </Suspense>
    </ErrorBoundary>
  );
}

function App(props: { bootstrap: boolean }) {
  const [host, setHost] = createSignal<HostState>();
  const [lifetime, setLifetime] = createSignal<AbortController>();
  const [activity, setActivity] = createSignal<Extract<HostUpdate, { type: "activity" }>>();
  const [finished, setFinished] = createSignal<number>();
  const [retry, setRetry] = createSignal(false);
  const [message, setMessage] = createSignal("");
  const [alreadyHosting, setAlreadyHosting] = createSignal(false);
  const [now, setNow] = createSignal(Date.now());
  const [localStart, setLocalStart] = createSignal<number>();
  const [sound, setSound] = createSignal(true);
  const [treeOpen, setTreeOpen] = createSignal(false);
  let chirp: ReturnType<typeof turnSounds>;
  let mounted = true;
  const queryClient = useQueryClient();
  const checkVisitor = createVisitorCheck();
  const visitor = useQuery(() => ({
    queryKey: visitorKey,
    queryFn: ({ signal }) => checkVisitor(signal),
    // one check already tries multiple hosts. don't replay the whole heartbeat.
    retry: false,
    refetchInterval: ({ state }) => {
      if (state.status === "error") return 8_000 + Math.random() * 4_000;
      return state.data === null ? 40_000 : HEARTBEAT_MS;
    },
    refetchIntervalInBackground: true,
    staleTime: 5_000,
    throwOnError: false,
  }));
  const hosting = createMemo(() => {
    const current = host();
    return current?.type === "hosting" ? current : undefined;
  });
  const observed = () => (visitor.isSuccess && !visitor.isPaused ? visitor.data : undefined);
  const unavailable = () => hosting() === undefined && observed() === null;
  const canVolunteer = () => observed() != null;
  // retain the clock on a failed refetch, but clear it on verified final-host loss.
  const startedAt = createMemo(
    () =>
      hosting()?.startedAt ??
      (visitor.data === null ? null : (visitor.data?.startedAt ?? localStart())),
  );
  const ticking = () => typeof startedAt() === "number";
  const shouldWarn = turnWarning();
  createEffect(() => {
    now();
    const current = hosting();
    if (
      current &&
      !lifetime()?.signal.aborted &&
      shouldWarn(current.runID, current.endsAt, Date.now())
    )
      chirp?.play("warning");
  });
  createEffect(() => {
    if (!ticking()) return;
    const timer = setInterval(() => setNow(Date.now()), 1_000);
    onCleanup(() => clearInterval(timer));
  });
  const active = createMemo(() => hosting() !== undefined);
  createEffect(() => {
    if (active()) onCleanup(protectHostingTab());
  });
  createEffect(() => {
    if (!unavailable()) return;
    setAlreadyHosting(false);
    if (!props.bootstrap && host()?.type === "waiting") lifetime()?.abort(new NoReachableHost());
  });
  onCleanup(() => {
    mounted = false;
    lifetime()?.abort();
    closeChirp();
    document.title = "can we keep this alive?";
  });
  const hosts = () => hosting()?.hosts ?? observed()?.hosts ?? 0;
  const visitors = () => hosting()?.tabs ?? observed()?.tabs ?? 0;
  const origin = () => hosting()?.origin ?? observed()?.host.origin;
  const focus = () => hosting()?.runID ?? observed()?.host.runID;
  const treeTarget = createMemo(() => {
    const address = origin();
    const run = focus();
    return address !== undefined && run !== undefined ? { origin: address, focus: run } : undefined;
  });
  const clockText = () => {
    const start = startedAt();
    return start === null ? "00h 00m 00s" : start === undefined ? "—" : age(start, now());
  };

  function closeChirp() {
    chirp?.close();
    chirp = undefined;
  }

  function toggleSound() {
    const enabled = !sound();
    setSound(enabled);
    if (!enabled) closeChirp();
    else if (lifetime() !== undefined) chirp = turnSounds();
  }

  async function start() {
    if (lifetime() !== undefined || (!props.bootstrap && !canVolunteer())) return;
    const stop = new AbortController();
    // audio permission must be requested during the click, before loading code.
    if (sound()) chirp = turnSounds();
    batch(() => {
      setLifetime(stop);
      setActivity(undefined);
      setFinished(undefined);
      setRetry(false);
      setMessage("");
      setAlreadyHosting(false);
    });
    let hosted = false;
    try {
      const { takeTurn } = await loadTurn(stop.signal);
      stop.signal.throwIfAborted();
      const result = await takeTurn(
        props.bootstrap,
        stop.signal,
        (next) => {
          if (!mounted) return;
          if (next.type === "checking") chirp?.play("invitation");
          if (next.type === "hosting") {
            hosted = true;
            setLocalStart(next.startedAt);
          }
          document.title =
            next.type === "hosting" ? "hosting · keepalive" : "can we keep this alive?";
          setHost(next);
        },
        setActivity,
      );
      if (!mounted) return;
      switch (result.type) {
        case "finished":
          if (result.hosted) setFinished(result.requests);
          setMessage(
            result.expired
              ? "Your turn is over. Thanks for hosting."
              : result.hosted
                ? "Thanks for hosting."
                : "This tab stopped.",
          );
          break;
        case "already-hosting":
          setAlreadyHosting(true);
          break;
        case "no-host":
          await queryClient.cancelQueries({ queryKey: visitorKey });
          queryClient.setQueryData<Observation | null>(visitorKey, null);
          break;
        case "failed":
          setRetry(!stop.signal.aborted);
          setMessage(result.message);
          break;
        case "observation-owned":
          break;
      }
    } catch {
      if (!mounted) return;
      // a failed lazy import is retryable; stopping during it starts no turn.
      setRetry(!stop.signal.aborted);
      setMessage(
        stop.signal.aborted
          ? "This tab stopped."
          : "This tab couldn't load the hosting code. Try again.",
      );
    } finally {
      closeChirp();
      if (mounted) {
        document.title = "can we keep this alive?";
        batch(() => {
          setHost(undefined);
          setLifetime(undefined);
        });
        if (hosted) void visitor.refetch();
      }
    }
  }

  const status = () => {
    const current = host();
    if (unavailable() && (current === undefined || current.type === "waiting"))
      return "No host is serving the site right now.";
    if (!canVolunteer() && current?.type === "waiting") return "Checking for a host…";
    if (current !== undefined)
      return current.type === "copying" && current.bootstrap
        ? "Copying the site to this tab…"
        : labels[current.type];
    if (lifetime()) return "Loading hosting code…";
    if (!props.bootstrap && !canVolunteer()) return "Checking for a host…";
    return message() || "You can help keep it online.";
  };

  return (
    <>
      <p class="experiment-age">
        <span>alive for</span>
        <strong>{clockText()}</strong>
      </p>
      <Show
        when={
          !props.bootstrap &&
          canVolunteer() &&
          lifetime() === undefined &&
          finished() === undefined &&
          !retry()
        }
      >
        <p>Click below to volunteer, then keep this tab open. You can stop anytime.</p>
      </Show>
      <section aria-label="keepalive">
        <p role="status">
          <Show when={alreadyHosting()} fallback={status()}>
            Keepalive is already running. <a href={`https://${fleet.site}`}>Visit the main site</a>{" "}
            to volunteer.
          </Show>
        </p>
        <Show when={host()}>
          <Suspense>
            <TurnView host={host()} activity={activity()} now={now()} />
          </Suspense>
        </Show>
        <Show when={finished() !== undefined}>
          <p>
            {props.bootstrap || canVolunteer()
              ? `You can close this tab or ${props.bootstrap ? "host" : "volunteer"} again.`
              : "You can close this tab."}
          </p>
          <p>{pluralRequests(finished() ?? 0)} handled</p>
        </Show>
        <p>
          {unavailable()
            ? "0 reachable hosts"
            : hosts() === 0
              ? "— tabs · — hosts"
              : `~${visitors().toLocaleString()} ${visitors() === 1 ? "tab" : "tabs"} · ${hosts().toLocaleString()} ${hosts() === 1 ? "host" : "hosts"}`}
        </p>
        <Show when={hosting()?.saturated ?? observed()?.saturated}>
          <p>Some hosts aren’t shown.</p>
        </Show>
        <Show when={treeTarget()}>
          {(target) => (
            <details
              class="host-details"
              onToggle={(event) => setTreeOpen(event.currentTarget.open)}
            >
              <summary>hosts</summary>
              <Show when={treeOpen()}>
                <HostPanel
                  origin={target().origin}
                  focus={target().focus}
                  self={hosting()?.runID}
                  now={now()}
                />
              </Show>
            </details>
          )}
        </Show>
      </section>
      <div class="actions">
        <Show when={!alreadyHosting()}>
          <Show
            when={lifetime()}
            fallback={
              <Show when={props.bootstrap || canVolunteer()}>
                <button type="button" onClick={() => void start()}>
                  {retry()
                    ? "try again"
                    : finished() !== undefined
                      ? props.bootstrap
                        ? "host again"
                        : "volunteer again"
                      : props.bootstrap
                        ? "start hosting"
                        : "i'll keep it alive"}
                </button>
              </Show>
            }
          >
            <button
              type="button"
              onClick={() => lifetime()?.abort()}
              disabled={host()?.type === "stopping"}
            >
              stop
            </button>
            <button
              class="text-action"
              type="button"
              onClick={toggleSound}
              aria-pressed={sound()}
              title="Play an invitation sound in the background and a warning each minute in the final five minutes"
            >
              sound: {sound() ? "on" : "off"}
            </button>
          </Show>
        </Show>
      </div>
    </>
  );
}

const root = document.getElementById("app");
if (root !== null) {
  const client = new QueryClient();
  render(() => {
    onCleanup(() => client.clear());
    return (
      <QueryClientProvider client={client}>
        <App bootstrap={root.hasAttribute("data-start")} />
      </QueryClientProvider>
    );
  }, root);
}
