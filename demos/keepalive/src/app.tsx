import { render } from "preact";
import { useEffect, useState } from "preact/hooks";
import { hostTab, type HostState } from "./hosting/tab.ts";

const labels = {
  copying: "Downloading files to serve visitors…",
  waiting: "Waiting to host…",
  starting: "Starting to host…",
  hosting: "This tab is hosting.",
  stopping: "Stopping…",
} as const;

function age(since: number) {
  const minutes = Math.floor(Math.max(0, Date.now() - since) / 60_000);
  if (minutes < 1) return "less than a minute";
  if (minutes < 60) return `${minutes}m`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

function countdown(endsAt: number, now: number) {
  const seconds = Math.max(0, Math.ceil((endsAt - now) / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

function App({ bootstrap }: { bootstrap: boolean }) {
  const [host, setHost] = useState<HostState>();
  const [lifetime, setLifetime] = useState<{ stop: AbortController; replace: AbortController }>();
  const [replacing, setReplacing] = useState(false);
  const [message, setMessage] = useState("");
  const [now, setNow] = useState(Date.now);
  const endsAt = host?.type === "hosting" ? host.endsAt : undefined;
  useEffect(() => {
    if (endsAt === undefined) return;
    const timer = setInterval(() => setNow(Date.now()), 250);
    setNow(Date.now());
    return () => clearInterval(timer);
  }, [endsAt]);

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
        ({ expired }) =>
          setMessage(expired ? "Your 30-minute turn is over." : "This tab stopped hosting."),
        () =>
          setMessage(
            stop.signal.aborted
              ? "This tab stopped."
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
          this tab open to serve the site. Each turn lasts up to 30 minutes.
        </p>
      ) : (
        <>
          <p>This site runs in people's browsers.</p>
          <p>
            Keep this tab open and it'll host when needed, for up to 30 minutes. You can stop
            anytime.
          </p>
        </>
      )}
      <section aria-label="keepalive">
        <p role="status">
          {host === undefined ? message || "You can help keep it online." : labels[host.type]}
        </p>
        {host?.type === "copying" && <CopyProgress received={host.received} total={host.total} />}
        {host?.type === "hosting" && (
          <ul>
            <li>hosting for {age(host.since)}</li>
            <li>hosting ends in {countdown(host.endsAt, Math.max(now, host.since))}</li>
            <li>{host.filesServed} files served by this tab</li>
            <li>about {host.hosts} hosts seen</li>
            <li>experiment age: {age(host.startedAt)}</li>
          </ul>
        )}
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
        an experiment from <a href="https://tnl.dev">tnl</a> ·{" "}
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
