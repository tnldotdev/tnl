import type { Action, Pin } from "./model.ts";

const allowedTags = new Set([
  "a",
  "button",
  "div",
  "span",
  "p",
  "label",
  "form",
  "input",
  "textarea",
  "select",
  "option",
  "ul",
  "li",
  "strong",
  "em",
  "h1",
  "h2",
  "h3",
]);
const omittedTags = new Set(["script", "style", "template", "iframe", "svg", "math"]);
const allowedAttributes = new Set([
  "id",
  "class",
  "role",
  "aria-label",
  "data-testid",
  "title",
  "name",
  "type",
]);

export function boundedText(value: string, bytes: number): string {
  const encoder = new TextEncoder();
  let result = "";
  let length = 0;
  for (const character of value) {
    length += encoder.encode(character).length;
    if (length > bytes) break;
    result += character;
  }
  return result;
}

export function elementLabel(element: Element): string {
  // form values and editable text are never used as semantic labels.
  const label = element.getAttribute("aria-label");
  if (label !== null) return boundedText(label.trim(), 256);
  let text = "";
  let visited = 0;
  function visit(node: Node): void {
    if (++visited > 64 || text.length >= 256) return;
    if (node.nodeType === Node.TEXT_NODE) {
      text += (node.textContent ?? "").slice(0, 256);
      return;
    }
    if (
      !(node instanceof Element) ||
      node.matches("input, textarea, option, [contenteditable]") ||
      omittedTags.has(node.localName)
    )
      return;
    for (const child of node.childNodes) {
      if (visited >= 64) break;
      visit(child);
    }
  }
  visit(element);
  return boundedText(text.trim(), 256);
}

export function capturePin(element: Element): Pin {
  const container = element.ownerDocument.createElement("div");
  let nodes = 0;
  function copy(source: Node, target: Node): void {
    if (++nodes > 64) return;
    if (source.nodeType === Node.TEXT_NODE) {
      target.appendChild(
        element.ownerDocument.createTextNode((source.textContent ?? "").slice(0, 256)),
      );
      return;
    }
    if (
      !(source instanceof Element) ||
      omittedTags.has(source.localName) ||
      source.hasAttribute("contenteditable")
    )
      return;
    const destination = allowedTags.has(source.localName)
      ? element.ownerDocument.createElement(source.localName)
      : element.ownerDocument.createElement("span");
    for (const attribute of Array.from(source.attributes)) {
      if (allowedAttributes.has(attribute.name))
        destination.setAttribute(attribute.name, boundedText(attribute.value, 256));
    }
    target.appendChild(destination);
    if (!source.matches("textarea, option, input"))
      for (const child of source.childNodes) {
        if (nodes >= 64) break;
        copy(child, destination);
      }
  }
  copy(element, container);
  return {
    kind: "element",
    role: element.getAttribute("role") ?? element.localName,
    label: elementLabel(element),
    ...(element.getAttribute("data-testid")
      ? { test_id: boundedText(element.getAttribute("data-testid") ?? "", 128) }
      : {}),
    html: boundedText(container.innerHTML, 2000),
  };
}

export function observeActions(
  document: Document,
  host: Element,
  onAction: (action: Action) => void,
): () => void {
  function observe(event: Event): void {
    if (event.composedPath().includes(host)) return;
    const target = event.target;
    if (!(target instanceof Element)) return;
    const element = target.closest("button, a, input[type=submit], [role=button], form");
    if (!element) return;
    onAction({
      type: event.type === "submit" ? "submit" : "click",
      label: elementLabel(element),
      ...(element.getAttribute("data-testid")
        ? { test_id: boundedText(element.getAttribute("data-testid") ?? "", 128) }
        : {}),
    });
  }
  document.addEventListener("click", observe, true);
  document.addEventListener("submit", observe, true);
  return () => {
    document.removeEventListener("click", observe, true);
    document.removeEventListener("submit", observe, true);
  };
}
