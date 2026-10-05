import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { chromium } from "playwright";
import { expect, test } from "vitest";

test("the committed bundle runs in Shadow DOM under CSP and tracks changing pins", async () => {
  const script = await readFile(new URL("./toolbar.js", import.meta.url));
  const id = "fb_0123456789abcdefghijkl";
  let state = "open";
  const report = {
    id,
    report: { text: "Use a clearer label", created_at: "2026-10-05T00:00:00Z" },
    element: { kind: "element", label: "Save", test_id: "save" },
    scope: { page_path: "/" },
    evidence: { actions: [], failed_requests: [] },
  };
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://localhost");
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
          const type =
            typeof input === "object" && input !== null && "type" in input ? input.type : "reply";
          state = type === "thread.resolved" ? "resolved" : "open";
          response.end(
            JSON.stringify({
              cursor: 2,
              feedback_id: id,
              actor: "reviewer",
              type,
              at: "2026-10-05T00:00:00Z",
            }),
          );
        });
      } else if (url.pathname.endsWith("/events"))
        response.end(JSON.stringify({ events: [], event_cursor: 0 }));
      else if (url.pathname.endsWith(id)) response.end(JSON.stringify({ ...report, state }));
      else response.end(JSON.stringify({ threads: [{ ...report, state }], event_cursor: 0 }));
      return;
    }
    response.setHeader("Content-Type", "text/html");
    response.setHeader(
      "Content-Security-Policy",
      "default-src 'none'; script-src 'nonce-toolbar-test'; style-src 'nonce-toolbar-test'; connect-src 'self'",
    );
    response.end(
      `<!doctype html><html><head><style nonce="toolbar-test">body{height:3000px}#app{margin-top:250px}</style><script type="module" nonce="toolbar-test" src="/__tnl/feedback/toolbar.fixture.js"></script></head><body><div id="app"><button data-testid="save">Save</button></div></body></html>`,
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const browser = await chromium.launch();
  try {
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
    const before = await pin.boundingBox();
    await page.evaluate(() => window.scrollBy(0, 20));
    await expect
      .poll(async () => (await pin.boundingBox())?.y)
      .toBe(Math.max(0, (before?.y ?? 0) - 20));
    await page.getByRole("button", { name: "Save", exact: true }).evaluate((node) => {
      node.textContent = "Changed";
    });
    await expect.poll(() => pin.count()).toBe(0);
    await page.getByRole("button", { name: "Use a clearer label" }).click();
    await page.getByRole("button", { name: "Resolve", exact: true }).click();
    await page.getByRole("button", { name: "Reopen", exact: true }).click();
    await page.getByRole("button", { name: "Resolve", exact: true }).waitFor();
    expect(errors).toEqual([]);
  } finally {
    await browser.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
