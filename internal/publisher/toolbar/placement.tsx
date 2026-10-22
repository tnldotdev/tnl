import { useEffect, useState } from "preact/hooks";
import { capturePoint, captureSelection, restoreAnchor, type AnchorTarget } from "./anchors.ts";

export function Placement({
  document,
  host,
  picked,
}: {
  document: Document;
  host: Element;
  picked: (target: AnchorTarget) => void;
}) {
  const [point, setPoint] = useState<{ x: number; y: number }>();
  useEffect(() => {
    const window = document.defaultView;
    if (!window) return;
    const move = (event: MouseEvent): void => {
      if (!event.composedPath().includes(host)) setPoint({ x: event.clientX, y: event.clientY });
    };
    const click = (event: MouseEvent): void => {
      const selection = document.getSelection();
      if (
        event.composedPath().includes(host) ||
        !(event.target instanceof Element) ||
        (selection && !selection.isCollapsed)
      )
        return;
      event.preventDefault();
      event.stopImmediatePropagation();
      const target = capturePoint(event.target, event.clientX, event.clientY);
      if (target) picked(target);
    };
    window.addEventListener("mousemove", move, true);
    window.addEventListener("click", click, true);
    return () => {
      window.removeEventListener("mousemove", move, true);
      window.removeEventListener("click", click, true);
    };
  }, [document, host, picked]);
  return point ? (
    <span
      class="placement-cursor"
      aria-hidden="true"
      ref={(node) => {
        if (node) {
          node.style.left = point.x + "px";
          node.style.top = point.y + "px";
        }
      }}
    >
      [+]
    </span>
  ) : null;
}

export function SelectionHint({
  document,
  picked,
}: {
  document: Document;
  picked: (target: AnchorTarget) => void;
}) {
  const [target, setTarget] = useState<AnchorTarget>();
  useEffect(() => {
    const update = (): void => setTarget(captureSelection(document));
    document.addEventListener("selectionchange", update);
    document.addEventListener("scroll", update, true);
    document.defaultView?.addEventListener("resize", update);
    update();
    return () => {
      document.removeEventListener("selectionchange", update);
      document.removeEventListener("scroll", update, true);
      document.defaultView?.removeEventListener("resize", update);
    };
  }, [document]);
  if (!target) return null;
  const rect = restoreAnchor(document, target.anchor)?.range?.getClientRects()[0];
  if (!rect) return null;
  return (
    <button
      type="button"
      class="selection-hint"
      onMouseDown={(event) => event.preventDefault()}
      ref={(node) => {
        if (node) {
          node.style.top =
            Math.max(12, Math.min(rect.bottom + 4, (document.defaultView?.innerHeight ?? 0) - 44)) +
            "px";
          node.style.left =
            Math.max(12, Math.min(rect.left, (document.defaultView?.innerWidth ?? 0) - 112)) + "px";
        }
      }}
      onClick={() => {
        picked(target);
        setTarget(undefined);
      }}
    >
      [ comment ]
    </button>
  );
}
