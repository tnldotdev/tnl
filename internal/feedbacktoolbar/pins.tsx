import { useEffect, useRef, useState } from "preact/hooks";
import type { Summary } from "./model.ts";
import { restoreAnchor, supportedAnchor, type ResolvedAnchor } from "./anchors.ts";

export function Pins({
  document,
  threads,
  select,
}: {
  document: Document;
  threads: Summary[];
  select: (id: string) => void;
}) {
  const cache = useRef(new Map<string, ResolvedAnchor>());
  const [positions, setPositions] = useState<
    {
      id: string;
      top: number;
      left: number;
      changed: boolean;
      rectangles: { top: number; left: number; width: number; height: number }[];
    }[]
  >([]);
  useEffect(() => {
    const window = document.defaultView;
    if (!window) return;
    let frame = 0;
    const update = (): void => {
      frame = 0;
      setPositions(
        threads.flatMap((thread) => {
          const anchor = supportedAnchor(thread.anchor);
          if (thread.state === "resolved" || !anchor) return [];
          const restored = restoreAnchor(document, anchor, cache.current.get(thread.id));
          if (!restored) return [];
          cache.current.set(thread.id, restored);
          const rect = restored.element.getBoundingClientRect();
          if (!rect.width || !rect.height) return [];
          const rectangles = restored.range
            ? Array.from(restored.range.getClientRects())
                .slice(0, 64)
                .map((rect) => ({
                  top: rect.top,
                  left: rect.left,
                  width: rect.width,
                  height: rect.height,
                }))
            : [];
          const point = rectangles[0];
          return [
            {
              id: thread.id,
              top: point?.top ?? rect.top + anchor.y * rect.height,
              left: point?.left ?? rect.left + anchor.x * rect.width,
              changed: restored.textChanged,
              rectangles,
            },
          ];
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
      {positions.map((position, index) => (
        <div key={position.id}>
          {position.rectangles.map((rect, index) => (
            <span
              key={index}
              class={position.changed ? "highlight changed" : "highlight"}
              aria-hidden="true"
              ref={(node) => {
                if (node) {
                  node.style.top = rect.top + "px";
                  node.style.left = rect.left + "px";
                  node.style.width = rect.width + "px";
                  node.style.height = rect.height + "px";
                }
              }}
            />
          ))}
          <button
            type="button"
            class="pin"
            aria-label="Show pinned feedback"
            title={
              position.changed
                ? "text changed; original quote is in the conversation"
                : "show feedback"
            }
            ref={(button) => {
              if (button) {
                button.style.top = position.top + "px";
                button.style.left = position.left + "px";
              }
            }}
            onClick={() => select(position.id)}
          >
            [{index + 1}]
          </button>
        </div>
      ))}
    </>
  );
}
