import { useEffect, useRef, useState } from "preact/hooks";
import type { Summary } from "./model.ts";
import { restoreAnchor, supportedAnchor, type ResolvedAnchor } from "./anchors.ts";
import { Popover } from "./popover.tsx";

export function Pins({
  document,
  threads,
  select,
  selectedId,
}: {
  document: Document;
  threads: Summary[];
  select: (id: string) => void;
  selectedId?: string | undefined;
}) {
  const cache = useRef(new Map<string, ResolvedAnchor>());
  const [preview, setPreview] = useState<string>();
  const closing = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  function show(id: string): void {
    clearTimeout(closing.current);
    setPreview(id);
  }
  function hide(): void {
    clearTimeout(closing.current);
    closing.current = setTimeout(() => setPreview(undefined), 150);
  }
  useEffect(() => () => clearTimeout(closing.current), []);
  const [positions, setPositions] = useState<
    {
      thread: Summary;
      top: number;
      left: number;
      changed: boolean;
      rectangles: { top: number; left: number; width: number; height: number }[];
    }[]
  >([]);
  useEffect(() => {
    const window = document.defaultView;
    if (!window) return;
    const ids = new Set(threads.map((thread) => thread.id));
    for (const id of cache.current.keys()) if (!ids.has(id)) cache.current.delete(id);
    let frame = 0;
    const update = (): void => {
      frame = 0;
      setPositions(
        threads.flatMap((thread) => {
          const anchor = supportedAnchor(thread.anchor);
          if ((thread.state === "resolved" && thread.id !== selectedId) || !anchor) return [];
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
              thread,
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
  }, [document, threads, selectedId]);
  return (
    <>
      {positions.map((position) => (
        <div key={position.thread.id}>
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
            aria-label={"Show pinned feedback: " + position.thread.report.text}
            aria-pressed={position.thread.id === selectedId}
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
            onMouseEnter={() => show(position.thread.id)}
            onMouseLeave={hide}
            onFocus={() => show(position.thread.id)}
            onBlur={hide}
            onClick={() => {
              setPreview(undefined);
              select(position.thread.id);
            }}
          >
            [
            {position.thread.state === "resolved"
              ? "x"
              : position.thread.message_count > 9
                ? "9+"
                : position.thread.message_count}
            ]
          </button>
          {preview === position.thread.id && preview !== selectedId && (
            <Popover
              document={document}
              anchor={position.thread.anchor}
              fallback={document.body}
              title="feedback preview"
              entered={() => show(position.thread.id)}
              left={hide}
            >
              <div class="comment-meta">
                <span>{position.thread.report.author?.display_name ?? "anonymous"}</span>
                <span>
                  {position.thread.message_count}{" "}
                  {position.thread.message_count === 1 ? "message" : "messages"}
                </span>
              </div>
              <p class="pin-preview-text">{position.thread.report.text}</p>
              {supportedAnchor(position.thread.anchor)?.selection && (
                <blockquote class="pin-preview-text">
                  {supportedAnchor(position.thread.anchor)?.selection?.text}
                </blockquote>
              )}
              {position.changed && <small>text changed; the original quote is still saved</small>}
            </Popover>
          )}
        </div>
      ))}
    </>
  );
}
