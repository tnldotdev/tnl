import { render } from "preact";
import { useState } from "preact/hooks";
import { hostTab, type HostState } from "./hosting/tab.ts";

const labels = {
  copying: "Getting a copy of the site…",
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

function App({ bootstrap }: { bootstrap: boolean }) {
  const [host, setHost] = useState<HostState>();
  const [lifetime, setLifetime] = useState<{ stop: AbortController; replace: AbortController }>();
  const [replacing, setReplacing] = useState(false);
  const [message, setMessage] = useState("");

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
        () => setMessage("This tab stopped hosting."),
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
          this tab open to serve the site.
        </p>
      ) : (
        <>
          <p>This site runs in people's browsers.</p>
          <p>Keep this tab open and it'll start hosting when needed. You can stop anytime.</p>
        </>
      )}
      <section aria-label="keepalive">
        <p role="status">
          {host === undefined ? message || "You can help keep it online." : labels[host.type]}
        </p>
        {host?.type === "hosting" && (
          <ul>
            <li>hosting for {age(host.since)}</li>
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
              disabled={replacing}
              onClick={() => {
                setReplacing(true);
                lifetime.replace.abort();
              }}
            >
              {replacing ? "looking for another host…" : "find my replacement"}
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
        an experiment by <a href="https://tnl.dev">tnl</a> ·{" "}
        <a href="https://github.com/tnldotdev/tnl/tree/main/demos/keepalive">source</a>
      </footer>
    </main>
  );
}

const root = document.getElementById("app");
if (root !== null) render(<App bootstrap={root.hasAttribute("data-start")} />, root);
