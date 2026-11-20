import { ADMISSION_PATH } from "../enrollment.ts";

export function updateAdmission(
  origin: string,
  requestID: string,
  state: "reserve" | "ready" | "stop",
  signal: AbortSignal,
  bootstrap = false,
) {
  return fetch(new URL(ADMISSION_PATH, origin), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ requestID, state, ...(state === "reserve" ? { bootstrap } : {}) }),
    redirect: "error",
    signal,
  });
}

export async function reserveTurn(
  origin: string,
  requestID: string,
  bootstrap: boolean,
  signal: AbortSignal,
) {
  for (;;) {
    signal.throwIfAborted();
    const response = await updateAdmission(origin, requestID, "reserve", signal, bootstrap);
    await response.body?.cancel();
    if (response.ok) return;
    if (response.status !== 429 && response.status !== 503)
      throw new Error("Hosting admission was refused.");
    await waitForRetry(signal);
  }
}

export function waitForRetry(signal: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    const stop = () => {
      clearTimeout(timer);
      reject(signal.reason);
    };
    const timer = setTimeout(
      () => {
        signal.removeEventListener("abort", stop);
        resolve();
      },
      5_000 + Math.random() * 10_000,
    );
    signal.addEventListener("abort", stop, { once: true });
    if (signal.aborted) stop();
  });
}
