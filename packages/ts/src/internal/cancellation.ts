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
