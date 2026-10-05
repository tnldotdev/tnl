import {
  anchorSchema,
  type Anchor,
  type AnchorData,
  type ElementSnapshot,
  type TextBoundary,
} from "./model.ts";
import { captureElement } from "./evidence.ts";
import { finder } from "@medv/finder";

export type AnchorTarget = { anchor: Anchor; element: ElementSnapshot };

export function selectorAlternatives(element: Element): string[] {
  const selectors: string[] = [];
  function add(selector: string): void {
    if (selector.length > 512 || selectors.includes(selector)) return;
    try {
      if (element.ownerDocument.querySelectorAll(selector).length === 1) selectors.push(selector);
    } catch {
      /* selectors are best-effort locators */
    }
  }
  const testID = element.getAttribute("data-testid");
  if (testID) add(`[data-testid="${CSS.escape(testID)}"]`);
  if (element.id) add("#" + CSS.escape(element.id));
  for (const classes of [false, true])
    for (const ids of [true, false]) {
      try {
        add(
          finder(element, {
            root: element.ownerDocument.body,
            idName: () => ids,
            className: () => classes,
            attr: (name) => name === "data-testid",
            timeoutMs: 50,
            maxNumberOfPathChecks: 1000,
          }),
        );
      } catch {
        /* a disappeared element can still be described in the report */
      }
    }
  return selectors.slice(0, 6);
}

export function supportedAnchor(data: AnchorData | undefined): Anchor | undefined {
  const parsed = anchorSchema.safeParse(data);
  return parsed.success ? parsed.data : undefined;
}

export function resolveElement(
  document: Document,
  selectors: string[],
  cached?: Element,
): Element | undefined {
  if (cached?.isConnected && cached.ownerDocument === document) return cached;
  for (const selector of selectors) {
    try {
      const matches = document.querySelectorAll(selector);
      if (matches.length === 1) return matches.item(0);
    } catch {
      /* malformed selectors cannot hide the conversation */
    }
  }
  return undefined;
}

export function capturePoint(
  element: Element,
  clientX: number,
  clientY: number,
): AnchorTarget | undefined {
  const selectors = selectorAlternatives(element);
  if (!selectors.length) return undefined;
  const rect = element.getBoundingClientRect();
  const fraction = (offset: number, size: number): number =>
    size > 0 ? Math.min(1, Math.max(0, offset / size)) : 0;
  return {
    anchor: {
      schema_version: 1,
      selectors,
      x: fraction(clientX - rect.left, rect.width),
      y: fraction(clientY - rect.top, rect.height),
    },
    element: captureElement(element),
  };
}

function textChildren(element: Element): Text[] {
  return Array.from(element.childNodes).filter(
    (node): node is Text => node.nodeType === Node.TEXT_NODE,
  );
}

function safeText(node: Text): boolean {
  return (
    !!node.parentElement &&
    !node.parentElement.closest(
      "script, style, template, input, textarea, [contenteditable], [data-tnl-feedback]",
    )
  );
}

export function captureSelection(document: Document): AnchorTarget | undefined {
  const selection = document.getSelection();
  if (!selection || !selection.rangeCount || selection.isCollapsed) return undefined;
  const range = selection.getRangeAt(0);
  if (
    range.startContainer.getRootNode() !== document ||
    range.endContainer.getRootNode() !== document
  )
    return undefined;
  const root = range.commonAncestorContainer;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const nodes: Text[] = [];
  if (root instanceof Text) nodes.push(root);
  else
    for (let node = walker.nextNode(); node && nodes.length < 2048; node = walker.nextNode()) {
      if (node instanceof Text && range.intersectsNode(node) && safeText(node)) nodes.push(node);
    }
  const included = nodes.filter(
    (node) =>
      safeText(node) &&
      (node !== range.startContainer || range.startOffset < node.length) &&
      (node !== range.endContainer || range.endOffset > 0),
  );
  const first = included[0],
    last = included.at(-1);
  if (!first?.parentElement || !last?.parentElement) return undefined;
  const startOffset = first === range.startContainer ? range.startOffset : 0;
  const endOffset = last === range.endContainer ? range.endOffset : last.length;
  const quote = included
    .map((node) =>
      node.data.slice(node === first ? startOffset : 0, node === last ? endOffset : node.length),
    )
    .join("");
  if (!quote.trim() || quote.length > 2000) return undefined;
  const start = {
    selectors: selectorAlternatives(first.parentElement),
    text_node: textChildren(first.parentElement).indexOf(first),
    offset: startOffset,
  };
  const end = {
    selectors: selectorAlternatives(last.parentElement),
    text_node: textChildren(last.parentElement).indexOf(last),
    offset: endOffset,
  };
  const element = root instanceof Element ? root : first.parentElement;
  const anchor: Anchor = {
    schema_version: 1,
    selectors: selectorAlternatives(element),
    x: 0,
    y: 0,
    selection: { start, end, text: quote },
  };
  return anchorSchema.safeParse(anchor).success
    ? { anchor, element: captureElement(element) }
    : undefined;
}

export type ResolvedAnchor = { element: Element; range?: Range | undefined; textChanged: boolean };

export function restoreAnchor(
  document: Document,
  anchor: Anchor,
  cached?: ResolvedAnchor,
): ResolvedAnchor | undefined {
  const element = resolveElement(document, anchor.selectors, cached?.element);
  if (!element) return undefined;
  if (!anchor.selection) return { element, textChanged: false };
  const boundary = (value: TextBoundary, cachedNode?: Node): Text | undefined => {
    const parent = resolveElement(document, value.selectors);
    const node =
      cachedNode instanceof Text && cachedNode.isConnected && cachedNode.ownerDocument === document
        ? cachedNode
        : parent
          ? textChildren(parent)[value.text_node]
          : undefined;
    return node && safeText(node) && value.offset <= node.length ? node : undefined;
  };
  const start = boundary(anchor.selection.start, cached?.range?.startContainer),
    end = boundary(anchor.selection.end, cached?.range?.endContainer);
  if (!start || !end) return { element, textChanged: true };
  try {
    const range = document.createRange();
    range.setStart(start, anchor.selection.start.offset);
    range.setEnd(end, anchor.selection.end.offset);
    if (range.collapsed) return { element, textChanged: true };
    return { element, range, textChanged: range.toString() !== anchor.selection.text };
  } catch {
    return { element, textChanged: true };
  }
}

export function beginPicking(
  document: Document,
  host: Element,
  picked: (target: AnchorTarget) => void,
  canceled: () => void,
): () => void {
  function click(event: MouseEvent): void {
    if (event.composedPath().includes(host) || !(event.target instanceof Element)) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    const target = capturePoint(event.target, event.clientX, event.clientY);
    if (target) {
      stop();
      picked(target);
    }
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
