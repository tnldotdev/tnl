import { useEffect, useState } from "preact/hooks";
import type { Pin, Summary } from "./model.ts";
import { capturePin, elementLabel } from "./evidence.ts";

export function matchPin(document: Document, pin: Pin): Element | undefined {
  if (pin.kind !== "element" || !pin.test_id) return undefined;
  const matches = Array.from(document.querySelectorAll("[data-testid]")).filter(
    (element) => element.getAttribute("data-testid") === pin.test_id,
  );
  const element = matches[0];
  return matches.length === 1 && element && elementLabel(element) === pin.label
    ? element
    : undefined;
}

export function beginPicking(
  document: Document,
  host: Element,
  picked: (pin: Pin) => void,
  canceled: () => void,
): () => void {
  function click(event: MouseEvent): void {
    if (event.composedPath().includes(host) || !(event.target instanceof Element)) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    stop();
    picked(capturePin(event.target));
  }
  function key(event: KeyboardEvent): void {
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopImmediatePropagation();
      stop();
      canceled();
    }
  }
  function stop(): void {
    document.removeEventListener("click", click, true);
    document.removeEventListener("keydown", key, true);
  }
  document.addEventListener("click", click, true);
  document.addEventListener("keydown", key, true);
  return stop;
}

export function Pins({
  document,
  threads,
  select,
}: {
  document: Document;
  threads: Summary[];
  select: (id: string) => void;
}) {
  const [positions, setPositions] = useState<{ id: string; top: number; left: number }[]>([]);
  useEffect(() => {
    const window = document.defaultView;
    if (!window) return;
    let frame = 0;
    const update = (): void => {
      frame = 0;
      setPositions(
        threads.flatMap((thread) => {
          if (thread.state === "resolved") return [];
          const element = matchPin(document, thread.element);
          if (!element) return [];
          const rect = element.getBoundingClientRect();
          return rect.width > 0 && rect.height > 0
            ? [{ id: thread.id, top: Math.max(0, rect.top - 6), left: Math.max(0, rect.left - 6) }]
            : [];
        }),
      );
    };
    const schedule = (): void => {
      if (!frame) frame = window.requestAnimationFrame(update);
    };
    const observer = new MutationObserver(schedule);
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true,
      attributes: true,
    });
    document.addEventListener("scroll", schedule, true);
    window.addEventListener("resize", schedule);
    update();
    return () => {
      observer.disconnect();
      document.removeEventListener("scroll", schedule, true);
      window.removeEventListener("resize", schedule);
      window.cancelAnimationFrame(frame);
    };
  }, [document, threads]);
  return (
    <>
      {positions.map((position) => (
        <button
          key={position.id}
          type="button"
          class="pin"
          aria-label="Show pinned feedback"
          ref={(button) => {
            // set individual CSS properties so the page's style-src-attr
            // policy can stay restrictive; no inline style string is assigned.
            if (button) {
              button.style.top = position.top + "px";
              button.style.left = position.left + "px";
            }
          }}
          onClick={() => select(position.id)}
        />
      ))}
    </>
  );
}
