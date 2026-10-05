// @vitest-environment jsdom
import { expect, test } from "vitest";
import { capturePin, observeActions } from "./evidence.ts";
import { matchPin } from "./pins.tsx";
import type { Action } from "./model.ts";

test("element evidence excludes executable markup, form values, editable text, and URLs", () => {
  const element = document.createElement("div");
  element.innerHTML =
    '<button data-testid="save" onclick="secret()">Save</button><input value="secret"><textarea>private</textarea><div contenteditable>typed secret</div><script>secret()</script><a href="/?token=secret">Go</a>';
  const pin = capturePin(element);
  expect(pin.html).toContain('data-testid="save"');
  for (const forbidden of ["secret", "private", "onclick", "href=", "<script>"])
    expect(pin.html).not.toContain(forbidden);
  expect(pin.label).not.toContain("secret");
  expect(pin.label).not.toContain("private");
  expect(capturePin(document.createElement("textarea")).label).toBe("");
});

test("a pin needs a unique current element and matching label", () => {
  const app = document.createElement("div");
  app.innerHTML = '<button data-testid="save">Save</button>';
  document.body.append(app);
  const element = app.firstElementChild;
  if (!element) throw new Error("fixture missing");
  const pin = capturePin(element);
  expect(matchPin(document, pin)).toBe(element);
  element.textContent = "Changed";
  expect(matchPin(document, pin)).toBeUndefined();
  element.textContent = "Save";
  app.append(element.cloneNode(true));
  expect(matchPin(document, pin)).toBeUndefined();
  app.remove();
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
