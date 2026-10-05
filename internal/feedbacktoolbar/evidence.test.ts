// @vitest-environment jsdom
import { expect, test } from "vitest";
import { captureElement, observeActions } from "./evidence.ts";
import type { Action } from "./model.ts";

test("element evidence excludes executable markup, form values, editable text, and URLs", () => {
  const element = document.createElement("div");
  element.innerHTML =
    '<button data-testid="save" onclick="secret()">Save</button><input value="secret"><textarea>private</textarea><div contenteditable>typed secret</div><script>secret()</script><a href="/?token=secret">Go</a>';
  const pin = captureElement(element);
  expect(pin.html).toContain('data-testid="save"');
  for (const forbidden of ["secret", "private", "onclick", "href=", "<script>"])
    expect(pin.html).not.toContain(forbidden);
  expect(pin.label).not.toContain("secret");
  expect(pin.label).not.toContain("private");
  expect(captureElement(document.createElement("textarea")).label).toBe("");
});

test("activity excludes the toolbar and ignores typed input values", () => {
  const host = document.createElement("div");
  const shadow = host.attachShadow({ mode: "open" });
  const button = document.createElement("button");
  button.textContent = "Resolve";
  shadow.append(button);
  document.body.append(host);
  const actions: Action[] = [];
  const stop = observeActions(document, host, (action) => actions.push(action));
  button.click();
  expect(actions).toEqual([]);
  stop();
  host.remove();
});
