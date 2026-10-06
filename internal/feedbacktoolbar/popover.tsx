import { useEffect, useRef } from "preact/hooks";
import type { ComponentChildren } from "preact";
import {
  autoUpdate,
  computePosition,
  flip,
  offset,
  shift,
  size,
  type VirtualElement,
} from "@floating-ui/dom";
import { supportedAnchor, restoreAnchor, type ResolvedAnchor } from "./anchors.ts";
import type { AnchorData } from "./model.ts";
import { AsciiBar } from "./frame.tsx";

export function Popover({
  document,
  anchor,
  fallback,
  title,
  close,
  entered,
  left,
  children,
}: {
  document: Document;
  anchor?: AnchorData | undefined;
  fallback: Element;
  title: string;
  close?: (() => void) | undefined;
  entered?: (() => void) | undefined;
  left?: (() => void) | undefined;
  children: ComponentChildren;
}) {
  const node = useRef<HTMLElement>(null);
  const cached = useRef<ResolvedAnchor | undefined>(undefined);
  const cacheKey = useRef("");
  useEffect(() => {
    const floating = node.current;
    if (!floating) return;
    const nextKey = JSON.stringify(anchor ?? null);
    if (cacheKey.current !== nextKey) {
      cached.current = undefined;
      cacheKey.current = nextKey;
    }
    const current = supportedAnchor(anchor);
    const reference: VirtualElement = {
      contextElement: current ? (restoreAnchor(document, current)?.element ?? fallback) : fallback,
      getBoundingClientRect: () => {
        const restored = current ? restoreAnchor(document, current, cached.current) : undefined;
        if (!restored) return fallback.getBoundingClientRect();
        cached.current = restored;
        const rangeRect = restored.range?.getClientRects()[0];
        if (rangeRect) return rangeRect;
        const rect = restored.element.getBoundingClientRect();
        return new DOMRect(
          rect.left + (current?.x ?? 0) * rect.width,
          rect.top + (current?.y ?? 0) * rect.height,
          1,
          1,
        );
      },
    };
    const update = (): void => {
      void computePosition(reference, floating, {
        strategy: "fixed",
        placement: "right-start",
        middleware: [
          offset(12),
          flip(),
          shift({ padding: 12 }),
          size({
            padding: 12,
            apply: ({ availableHeight }) => {
              floating.style.maxHeight = Math.max(0, availableHeight) + "px";
            },
          }),
        ],
      }).then(({ x, y }) => {
        floating.style.left = x + "px";
        floating.style.top = y + "px";
      });
    };
    const cleanup = autoUpdate(reference, floating, update, {
      elementResize: typeof ResizeObserver !== "undefined",
      layoutShift: typeof IntersectionObserver !== "undefined",
    });
    const observer = new MutationObserver(update);
    observer.observe(document.body, { subtree: true, childList: true, characterData: true });
    return () => {
      cleanup();
      observer.disconnect();
    };
  }, [document, anchor, fallback]);
  return (
    <aside ref={node} class="popover" aria-label={title} onMouseEnter={entered} onMouseLeave={left}>
      <AsciiBar title={title} {...(close ? { close } : {})} />
      <div class="panel-body">{children}</div>
      <AsciiBar />
    </aside>
  );
}
