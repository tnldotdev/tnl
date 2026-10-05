import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { chromium, type Browser } from "playwright";
import { expect, test } from "vitest";

test("the committed bundle runs in Shadow DOM under CSP and tracks changing pins", async () => {
  const script = await readFile(new URL("./toolbar.js", import.meta.url));
  const font = await readFile(
    new URL("../browserfonts/fira-code-latin-wght-normal.woff2", import.meta.url),
  );
  const id = "fb_0123456789abcdefghijkl";
  let state = "open";
  const report = {
    schema_version: 1,
    id,
    report: { text: "Use a clearer label", created_at: "2026-10-05T00:00:00Z" },
    anchor: { schema_version: 1, selectors: ['[data-testid="save"]'], x: 0, y: 0 },
    scope: { page_path: "/" },
    evidence: { schema_version: 1, actions: [], failed_requests: [] },
  };
  let currentText = report.report.text;
  let currentAnchor: unknown = report.anchor;
  let currentEvidence: unknown = report.evidence;
  const snapshot = () => ({
    ...report,
    state,
    anchor: currentAnchor,
    evidence: currentEvidence,
    report: { ...report.report, text: currentText },
  });
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://localhost");
    if (url.pathname === "/__tnl/feedback/fira-code.woff2") {
      response.setHeader("Content-Type", "font/woff2");
      response.end(font);
      return;
    }
    if (url.pathname === "/__tnl/feedback/toolbar.fixture.js") {
      response.setHeader("Content-Type", "text/javascript");
      response.end(script);
      return;
    }
    if (url.pathname.startsWith("/__tnl/feedback")) {
      response.setHeader("Content-Type", "application/json");
      if (request.method === "POST") {
        const chunks: Buffer[] = [];
        request.on("data", (chunk: Buffer) => chunks.push(chunk));
        request.on("end", () => {
          const input: unknown = JSON.parse(Buffer.concat(chunks).toString());
          if (
            url.pathname === "/__tnl/feedback" &&
            typeof input === "object" &&
            input !== null &&
            "text" in input &&
            typeof input.text === "string"
          ) {
            currentText = input.text;
            currentAnchor = "anchor" in input ? input.anchor : undefined;
            currentEvidence = "evidence" in input ? input.evidence : report.evidence;
            response.end(JSON.stringify(snapshot()));
            return;
          }
          const type =
            typeof input === "object" && input !== null && "type" in input ? input.type : "reply";
          state = type === "thread.resolved" ? "resolved" : "open";
          response.end(
            JSON.stringify({
              schema_version: 1,
              cursor: 2,
              feedback_id: id,
              actor: "reviewer",
              type,
              at: "2026-10-05T00:00:00Z",
            }),
          );
        });
      } else if (url.pathname.endsWith("/events"))
        response.end(JSON.stringify({ schema_version: 1, events: [], event_cursor: 0 }));
      else if (url.pathname.endsWith(id)) response.end(JSON.stringify(snapshot()));
      else if (url.pathname.endsWith("/evidence"))
        response.end(JSON.stringify({ schema_version: 1, failed_requests: [] }));
      else
        response.end(JSON.stringify({ schema_version: 1, threads: [snapshot()], event_cursor: 0 }));
      return;
    }
    response.setHeader("Content-Type", "text/html; charset=utf-8");
    response.setHeader(
      "Content-Security-Policy",
      "default-src 'none'; script-src 'nonce-toolbar-test'; style-src 'nonce-toolbar-test'; font-src 'self'; connect-src 'self'",
    );
    response.end(
      `<!doctype html><html><head><style nonce="toolbar-test">body{height:3000px}#app{margin-top:250px}</style><script type="module" nonce="toolbar-test" src="/__tnl/feedback/toolbar.fixture.js"></script></head><body><div id="app"><button data-testid="save">Save</button><p id="intro">A🙂 <strong>world</strong> end</p></div></body></html>`,
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  let browser: Browser | undefined;
  try {
    browser = await chromium.launch();
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("missing browser fixture listener");
    const page = await browser.newPage();
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.goto("http://127.0.0.1:" + address.port);
    await page.getByRole("button", { name: "Feedback", exact: true }).click();
    const pin = page.getByRole("button", { name: "Show pinned feedback" });
    await expect.poll(() => pin.count()).toBe(1);
    expect(
      await page.getByRole("complementary").evaluate((node) => getComputedStyle(node).position),
    ).toBe("fixed");
    expect(
      await page.getByRole("complementary").evaluate((node) => getComputedStyle(node).borderRadius),
    ).toBe("0px");
    expect(
      await page.getByRole("complementary").evaluate((node) => getComputedStyle(node).boxShadow),
    ).toBe("none");
    await expect
      .poll(() =>
        page.evaluate(() =>
          Array.from(document.fonts).some(
            (font) =>
              font.family.replace(/["']/g, "") === "tnl Fira Code" && font.status === "loaded",
          ),
        ),
      )
      .toBe(true);
    const before = await pin.boundingBox();
    await page.evaluate(() => window.scrollBy(0, 20));
    await expect
      .poll(async () => (await pin.boundingBox())?.y)
      .toBe(Math.max(0, (before?.y ?? 0) - 20));
    await page.getByRole("button", { name: "Save", exact: true }).evaluate((node) => {
      node.textContent = "Changed";
    });
    await expect.poll(() => pin.count()).toBe(1);
    await page.getByRole("button", { name: "Use a clearer label" }).click();
    await page.getByRole("button", { name: /^resolve$/i }).click();
    await page.getByRole("button", { name: /^reopen$/i }).click();
    await page.getByRole("button", { name: /^resolve$/i }).waitFor();
    await page.getByRole("button", { name: /^back to feedback$/i }).click();
    await page.evaluate(() => {
      const start = document.querySelector("#intro")?.firstChild;
      const end = document.querySelector("#intro strong")?.firstChild;
      if (!start || !end) throw new Error("selection fixture missing");
      const range = document.createRange();
      range.setStart(start, 1);
      range.setEnd(end, 5);
      document.getSelection()?.removeAllRanges();
      document.getSelection()?.addRange(range);
    });
    await page.getByRole("button", { name: /^use selected text$/i }).click();
    await page.getByRole("textbox", { name: /^feedback$/i }).fill("A text selection suggestion");
    await page.getByRole("button", { name: /^review feedback$/i }).click();
    await page.getByRole("button", { name: /^send feedback$/i }).click();
    await page.getByRole("heading", { name: "A text selection suggestion" }).waitFor();
    await expect.poll(() => page.locator(".highlight").count()).toBeGreaterThan(0);
    const rectangles = await page.locator(".highlight").count();
    await page.locator("#intro").evaluate((node) => {
      if (node instanceof HTMLElement) {
        node.style.width = "20px";
        node.style.overflowWrap = "anywhere";
      }
    });
    await expect.poll(() => page.locator(".highlight").count()).toBeGreaterThan(rectangles);
    await page.locator("#intro strong").evaluate((node) => {
      if (node.firstChild) node.firstChild.textContent = "Xworld";
    });
    await expect.poll(() => page.locator(".highlight.changed").count()).toBeGreaterThan(0);
    expect(await page.locator("blockquote").textContent()).toContain("🙂 world");
    await page.locator("#intro strong").evaluate((node) => node.remove());
    await expect.poll(() => page.locator(".highlight").count()).toBe(0);
    await expect.poll(() => pin.count()).toBe(1);
    expect(errors).toEqual([]);
  } finally {
    await browser?.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
