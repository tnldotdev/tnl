import { writeSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { chromium, type Browser } from "playwright";
import { expect, test } from "vitest";

test("the committed bundle runs in Shadow DOM under CSP and tracks changing pins", async () => {
  const started = performance.now();
  const counts = {
    session_responses: 0,
    page_errors: 0,
    request_failures: 0,
    reports: 0,
    cleanup_errors: 0,
  };
  // write before awaits: a test timeout must not depend on finally or console replay.
  function phase(name: string): void {
    try {
      writeSync(
        2,
        "toolbar browser fixture " +
          JSON.stringify({
            phase: name,
            elapsed_ms: Math.round(performance.now() - started),
            ...counts,
          }) +
          "\n",
      );
    } catch {
      // a closed diagnostic stream must not replace the test or cleanup failure.
    }
  }
  phase("read committed bundle");
  const script = await readFile(new URL("./toolbar.js", import.meta.url));
  phase("read committed font");
  const font = await readFile(
    new URL("../../browserfonts/fira-code-latin-wght-normal.woff2", import.meta.url),
  );
  let id = "fb_0123456789abcdefghijkl";
  let messageCount = 12;
  let cursor = 1;
  const reports: unknown[] = [];
  // clicking submit must not imply that the asynchronous report was saved.
  const acceptReport = Promise.withResolvers<void>();
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
    id,
    state: "open",
    message_count: messageCount,
    latest_event_cursor: cursor,
    anchor: currentAnchor,
    evidence: currentEvidence,
    report: { ...report.report, text: currentText },
  });
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://localhost");
    // matches the no-cookie response in ../browser_access.go.
    if (url.pathname === "/__tnl/team/session" && request.method === "GET") {
      response.setHeader("Content-Type", "application/json");
      response.end(JSON.stringify({ signed_in: false }) + "\n");
      return;
    }
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
        request.on("end", async () => {
          phase("report handler awaits acceptance");
          await acceptReport.promise;
          const input: unknown = JSON.parse(Buffer.concat(chunks).toString());
          if (
            url.pathname === "/__tnl/feedback" &&
            typeof input === "object" &&
            input !== null &&
            "text" in input &&
            typeof input.text === "string"
          ) {
            reports.push(input);
            counts.reports = Math.min(1000, counts.reports + 1);
            id = "fb_1123456789abcdefghijkl";
            messageCount = 1;
            cursor++;
            currentText = input.text;
            currentAnchor = "anchor" in input ? input.anchor : undefined;
            currentEvidence = "evidence" in input ? input.evidence : report.evidence;
            response.end(JSON.stringify(snapshot()));
            return;
          }
          response.writeHead(400).end();
        });
      } else if (url.pathname.endsWith("/events"))
        response.end(JSON.stringify({ schema_version: 1, events: [], event_cursor: cursor }));
      else if (url.pathname.endsWith(id)) response.end(JSON.stringify(snapshot()));
      else if (url.pathname.endsWith("/evidence"))
        response.end(JSON.stringify({ schema_version: 1, failed_requests: [] }));
      else
        response.end(
          JSON.stringify({ schema_version: 1, threads: [snapshot()], event_cursor: cursor }),
        );
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
  phase("listen on loopback");
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  let browser: Browser | undefined;
  const failures: unknown[] = [];
  try {
    phase("launch chrome");
    browser = await chromium.launch({ channel: "chrome" });
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("missing browser fixture listener");
    phase("create page");
    const page = await browser.newPage();
    const errors: string[] = [];
    let sessionResponseIsJSON = false;
    page.on("response", (response) => {
      if (
        response.request().method() === "GET" &&
        new URL(response.url()).pathname === "/__tnl/team/session"
      ) {
        counts.session_responses = Math.min(1000, counts.session_responses + 1);
        sessionResponseIsJSON =
          response.status() === 200 && response.headers()["content-type"] === "application/json";
      }
    });
    page.on("pageerror", () => {
      counts.page_errors = Math.min(1000, counts.page_errors + 1);
      if (errors.length < 1000) errors.push("page error");
    });
    page.on("requestfailed", () => {
      counts.request_failures = Math.min(1000, counts.request_failures + 1);
    });
    phase("navigate to fixture");
    await page.goto("http://127.0.0.1:" + address.port);
    const pin = page.getByRole("button", { name: /^Show pinned feedback/ });
    phase("wait for initial pin");
    await expect.poll(() => pin.count()).toBe(1);
    phase("read initial pin badge");
    expect(await pin.textContent()).toBe("[9+]");
    phase("hover pin");
    await pin.hover();
    phase("wait for pin preview");
    await page.getByRole("complementary", { name: "feedback preview", exact: true }).waitFor();
    phase("read preview message count");
    expect(
      await page
        .getByRole("complementary", { name: "feedback preview", exact: true })
        .textContent(),
    ).toContain("12 messages");
    phase("open feedback list");
    await page.getByRole("button", { name: "Feedback", exact: true }).click();
    phase("wait for feedback list");
    await page.getByRole("complementary", { name: "Feedback list panel", exact: true }).waitFor();
    phase("read list position");
    expect(
      await page
        .getByRole("complementary", { name: "Feedback list panel", exact: true })
        .evaluate((node) => getComputedStyle(node).position),
    ).toBe("fixed");
    phase("read list border radius");
    expect(
      await page
        .getByRole("complementary", { name: "Feedback list panel", exact: true })
        .evaluate((node) => getComputedStyle(node).borderRadius),
    ).toBe("0px");
    phase("read list shadow");
    expect(
      await page
        .getByRole("complementary", { name: "Feedback list panel", exact: true })
        .evaluate((node) => getComputedStyle(node).boxShadow),
    ).toBe("none");
    phase("wait for font");
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
    phase("read pin bounds");
    const before = await pin.boundingBox();
    phase("scroll page");
    await page.evaluate(() => window.scrollBy(0, 20));
    phase("wait for scrolled pin");
    await expect
      .poll(async () => (await pin.boundingBox())?.y)
      .toBe(Math.max(0, (before?.y ?? 0) - 20));
    phase("rename app button");
    await page.getByRole("button", { name: "Save", exact: true }).evaluate((node) => {
      node.textContent = "Changed";
    });
    phase("wait for pin after rename");
    await expect.poll(() => pin.count()).toBe(1);
    phase("close feedback list");
    await page.getByRole("button", { name: "Close feedback" }).click();
    const app = page.getByRole("button", { name: "Changed", exact: true });
    phase("observe app activation");
    await app.evaluate((node) =>
      node.addEventListener("click", () => node.setAttribute("data-activated", "true")),
    );
    phase("enter placement mode");
    await page.getByRole("button", { name: "Comment", exact: true }).click();
    phase("click app button");
    await app.click();
    phase("wait for placement composer");
    await page.getByRole("textbox", { name: /^feedback$/i }).waitFor();
    phase("check app click interception");
    expect(await app.getAttribute("data-activated")).toBeNull();
    phase("cancel placement composer");
    await page.getByRole("button", { name: /^cancel$/i }).click();
    phase("select fixture text");
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
    phase("wait for selection hint");
    await page.locator(".selection-hint").waitFor();
    phase("read selected text");
    expect(await page.evaluate(() => document.getSelection()?.toString())).toBe("🙂 world");
    phase("open selection composer");
    await page.locator(".selection-hint").click();
    phase("fill selection report");
    await page.getByRole("textbox", { name: /^feedback$/i }).fill("A text selection suggestion");
    phase("send selection report");
    await page.getByRole("button", { name: /^send feedback$/i }).click();
    phase("release report acceptance");
    acceptReport.resolve();
    phase("wait for saved report");
    await page.getByRole("heading", { name: "A text selection suggestion" }).waitFor();
    expect(reports).toHaveLength(1);
    phase("wait for initial highlights");
    await expect.poll(() => page.locator(".highlight").count()).toBeGreaterThan(0);
    phase("count initial highlights");
    const rectangles = await page.locator(".highlight").count();
    phase("wrap selected text");
    await page.locator("#intro").evaluate((node) => {
      if (node instanceof HTMLElement) {
        node.style.width = "20px";
        node.style.overflowWrap = "anywhere";
      }
    });
    phase("wait for wrapped highlights");
    await expect.poll(() => page.locator(".highlight").count()).toBeGreaterThan(rectangles);
    phase("change selected text");
    await page.locator("#intro strong").evaluate((node) => {
      if (node.firstChild) node.firstChild.textContent = "Xworld";
    });
    phase("wait for changed highlight");
    await expect.poll(() => page.locator(".highlight.changed").count()).toBeGreaterThan(0);
    phase("read original quote");
    expect(await page.locator("blockquote").textContent()).toContain("🙂 world");
    phase("remove selection endpoint");
    await page.locator("#intro strong").evaluate((node) => node.remove());
    phase("wait for highlights to disappear");
    await expect.poll(() => page.locator(".highlight").count()).toBe(0);
    phase("wait for final pin");
    await expect.poll(() => pin.count()).toBe(1);
    expect(errors).toEqual([]);
    expect(counts.session_responses).toBeGreaterThan(0);
    // the real consumer renders sign-in only after parsing a valid signed-out response.
    phase("wait for parsed signed-out session");
    await expect
      .poll(() => page.getByRole("link", { name: "[ sign in ]", exact: true }).count())
      .toBe(1);
    expect(sessionResponseIsJSON).toBe(true);
  } catch (cause) {
    failures.push(cause);
  } finally {
    phase("release report for cleanup");
    acceptReport.resolve();
    phase("close chrome");
    try {
      await browser?.close();
    } catch (cause) {
      counts.cleanup_errors++;
      failures.push(cause);
    }
    phase("close fixture server");
    try {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    } catch (cause) {
      counts.cleanup_errors++;
      failures.push(cause);
    }
    phase("cleanup complete");
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1)
    throw new AggregateError(failures, "browser fixture and cleanup failed", {
      cause: failures[0],
    });
});
