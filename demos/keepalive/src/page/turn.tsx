import {
  hostTab,
  AlreadyHosting,
  HostingInAnotherTab,
  HostingUnavailable,
  UploadTooSlow,
  type HostState,
} from "../hosting/tab.ts";
import { InvitationUnavailable } from "../peers/invitation.ts";
import { NoReachableHost } from "../network.ts";
import type { HostUpdate } from "../hosting/messages.ts";
import { Show } from "solid-js";
import { PULSE_SECONDS, requestPulse } from "../hosting/activity.ts";

function countdown(endsAt: number, now: number) {
  const seconds = Math.max(0, Math.ceil((endsAt - now) / 1_000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

export default function TurnView(props: {
  host: HostState | undefined;
  activity: Extract<HostUpdate, { type: "activity" }> | undefined;
  now: number;
}) {
  const copy = () => {
    const current = props.host;
    return current?.type === "copying" ? current : undefined;
  };
  const hosting = () => {
    const current = props.host;
    return current?.type === "hosting" ? current : undefined;
  };
  return (
    <>
      <Show when={copy()}>
        {(progress) => <CopyProgress received={progress().received} total={progress().total} />}
      </Show>
      <Show when={hosting()}>
        {(run) => (
          <>
            <p class="turn-countdown">
              {countdown(run().endsAt, Math.max(props.now, run().since))} left in your turn
            </p>
            <div class="host-activity">
              <div>
                serving ~{run().localTabs.toLocaleString()} of ~{run().tabs.toLocaleString()}{" "}
                {run().tabs === 1 ? "tab" : "tabs"}
              </div>
              <div class="request-line">
                <span class="request-pulse" aria-hidden="true">
                  {props.activity
                    ? requestPulse(props.activity.pulse, props.activity.second, props.now)
                    : "_".repeat(PULSE_SECONDS)}
                </span>
                <span>
                  {(props.activity?.requests ?? 0).toLocaleString()}{" "}
                  {props.activity?.requests === 1 ? "request" : "requests"}
                </span>
              </div>
            </div>
          </>
        )}
      </Show>
    </>
  );
}

function CopyProgress(props: { received: number; total: number }) {
  const filled = () => Math.floor((props.received / props.total) * 20);
  const mb = (bytes: number) => (bytes / 1_000_000).toFixed(1);
  return (
    <p
      class="copy-progress"
      role="progressbar"
      aria-label="Downloading hosting files"
      aria-valuemin={0}
      aria-valuemax={props.total}
      aria-valuenow={props.received}
    >
      <span aria-hidden="true">
        [{"#".repeat(filled())}
        {"-".repeat(20 - filled())}]
      </span>{" "}
      {mb(props.received)} / {mb(props.total)} MB
    </p>
  );
}

export async function takeTurn(
  bootstrap: boolean,
  signal: AbortSignal,
  update: (state: HostState) => void,
  activity: (state: Extract<HostUpdate, { type: "activity" }>) => void,
) {
  let hosted = false;
  try {
    const result = await hostTab(
      bootstrap,
      signal,
      (state) => {
        if (state.type === "hosting") hosted = true;
        update(state);
      },
      activity,
    );
    performance.mark("keepalive ended", { detail: result.expired ? "completed" : "stopped" });
    return { type: "finished", hosted, ...result } as const;
  } catch (error) {
    performance.mark("keepalive ended", {
      detail: signal.aborted
        ? "stopped"
        : error instanceof DOMException && error.name === "TimeoutError"
          ? "expired"
          : "failed",
    });
    if (error instanceof AlreadyHosting) return { type: "already-hosting" } as const;
    if (signal.reason instanceof NoReachableHost) return { type: "observation-owned" } as const;
    if (error instanceof NoReachableHost) return { type: "no-host" } as const;
    const message = signal.aborted
      ? "This tab stopped."
      : error instanceof HostingInAnotherTab
        ? "Another tab in this browser profile is hosting or waiting to host."
        : error instanceof HostingUnavailable
          ? "This tab couldn't start hosting. Try again later."
          : error instanceof InvitationUnavailable
            ? `${error.message} Try again.`
            : error instanceof UploadTooSlow
              ? "This tab couldn't complete the upload check. Try again."
              : "This tab couldn't host the site. Try again.";
    return { type: "failed", message } as const;
  }
}
