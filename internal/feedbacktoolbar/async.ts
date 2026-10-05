import { useEffect, useRef, useState } from "preact/hooks";

// every load belongs to a mounted view; changing page or thread unmounts it.
// mutation retries retain the exact body and key, even if the first response was lost.
export function useRequest() {
  const controller = useRef(new AbortController());
  const running = useRef(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => () => controller.current.abort(), []);
  async function run(operation: (signal: AbortSignal) => Promise<void>): Promise<void> {
    if (running.current || controller.current.signal.aborted) return;
    running.current = true;
    setPending(true);
    setError("");
    try {
      await operation(controller.current.signal);
    } catch (reason) {
      if (!controller.current.signal.aborted)
        setError(reason instanceof Error ? reason.message : "could not load feedback; try again");
    } finally {
      running.current = false;
      if (!controller.current.signal.aborted) setPending(false);
    }
  }
  return { run, pending, error };
}

export function mutationKey() {
  let previous = "";
  let key = "";
  return (body: unknown): string => {
    const identity = JSON.stringify(body);
    if (identity !== previous) {
      previous = identity;
      key = crypto.randomUUID();
    }
    return key;
  };
}
