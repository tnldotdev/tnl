/** stop waiting even when a provider ignores cancellation; observe late failures. */
export async function cancellable<Value>(
  signal: AbortSignal,
  run: () => Promise<Value>,
): Promise<Value> {
  signal.throwIfAborted();
  return new Promise<Value>((resolve, reject) => {
    const aborted = () => reject(signal.reason);
    signal.addEventListener("abort", aborted, { once: true });
    void Promise.resolve()
      .then(() => {
        signal.throwIfAborted();
        return run();
      })
      .then((value) => {
        signal.throwIfAborted();
        resolve(value);
      })
      .catch(reject)
      .finally(() => signal.removeEventListener("abort", aborted));
  });
}

// callers retain until across retries; finishing a phase never grants more time.
export function shutdownBudget(original?: number): {
  until: number;
  signal: AbortSignal;
  finish(): void;
} {
  const until = Math.min(original ?? Infinity, Date.now() + 10_000);
  const controller = new AbortController();
  const abort = () =>
    controller.abort(
      new DOMException("shutdown timed out; remote cleanup may be unconfirmed", "TimeoutError"),
    );
  const remaining = until - Date.now();
  const timer = setTimeout(abort, Math.max(0, remaining));
  if (remaining <= 0) abort();
  return { until, signal: controller.signal, finish: () => clearTimeout(timer) };
}
