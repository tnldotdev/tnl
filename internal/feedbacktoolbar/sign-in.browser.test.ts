import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { chromium, type Browser } from "playwright";
import { expect, test } from "vitest";
import { BrowserFeedbackEventRequest } from "../publisherapi/model.gen.ts";
import { reportInputSchema, type ReportInput } from "./model.ts";

test("sign-in opens a new tab while report and reply drafts remain under CSP", async () => {
  const script = await readFile(new URL("./toolbar.js", import.meta.url));
  const font = await readFile(
    new URL("../browserfonts/fira-code-latin-wght-normal.woff2", import.meta.url),
  );
  const id = "fb_0123456789abcdefghijkl";
  let required = true;
  let expired = false;
  let unavailable = false;
  let returned = false;
  let cursor = 1;
  let state: "open" | "resolved" = "open";
  const reports: ReportInput[] = [];
  const replies: string[] = [];
  const snapshot = () => ({
    schema_version: 1,
    id,
    state,
    message_count: 1 + replies.length,
    latest_event_cursor: cursor,
    report: {
      text: reports.at(-1)?.text ?? "Please use a clearer label",
      created_at: "2026-10-05T00:00:00Z",
    },
    scope: { page_path: "/preview?tab=review" },
    evidence: { schema_version: 1, actions: [], failed_requests: [] },
  });
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://localhost");
    const hasCookie = request.headers.cookie?.split("; ").includes("reviewer=sam") ?? false;
    const signedIn = hasCookie && !expired;
    if (url.pathname === "/__tnl/team/login") {
      const path = url.searchParams.get("return");
      if (!path?.startsWith("/") || path.startsWith("//")) {
        response.writeHead(400).end();
        return;
      }
      response
        .writeHead(303, { Location: "/oidc/callback?return=" + encodeURIComponent(path) })
        .end();
      return;
    }
    if (url.pathname === "/oidc/callback") {
      returned = true;
      expired = false;
      response
        .writeHead(303, {
          Location: url.searchParams.get("return") ?? "/",
          "Set-Cookie": "reviewer=sam; Path=/; HttpOnly; SameSite=Lax",
        })
        .end();
      return;
    }
    if (url.pathname === "/__tnl/team/logout") {
      response.writeHead(204, { "Set-Cookie": "reviewer=; Path=/; Max-Age=0; HttpOnly" }).end();
      return;
    }
    if (url.pathname === "/__tnl/team/session") {
      response.setHeader("Content-Type", "application/json");
      response.end(
        JSON.stringify(
          signedIn
            ? { signed_in: true, display_name: "Sam", visit_allowed: false }
            : { signed_in: false },
        ),
      );
      return;
    }
    if (url.pathname === "/__tnl/feedback/toolbar.fixture.js") {
      response.setHeader("Content-Type", "text/javascript");
      response.end(script);
      return;
    }
    if (url.pathname === "/__tnl/feedback/fira-code.woff2") {
      response.setHeader("Content-Type", "font/woff2");
      response.end(font);
      return;
    }
    if (url.pathname.startsWith("/__tnl/feedback")) {
      response.setHeader("Content-Type", "application/json");
      response.setHeader("Cache-Control", "no-store");
      if (url.pathname.endsWith("/access")) {
        if (unavailable) {
          response.writeHead(503).end("private-provider-secret");
          return;
        }
        response.end(
          JSON.stringify({
            require_sign_in: required,
            sign_in_available: true,
            identity_state: signedIn ? "signed_in" : hasCookie ? "expired" : "anonymous",
            ...(signedIn ? { identity: { identity_id: "external-sam", display_name: "Sam" } } : {}),
          }),
        );
        return;
      }
      if (request.method === "POST") {
        if (hasCookie && expired) {
          response.writeHead(403).end();
          return;
        }
        if (required && !signedIn) {
          response.writeHead(401).end();
          return;
        }
        const chunks: Buffer[] = [];
        request.on("data", (chunk: Buffer) => chunks.push(chunk));
        request.on("end", () => {
          const input: unknown = JSON.parse(Buffer.concat(chunks).toString());
          if (url.pathname === "/__tnl/feedback") {
            const report = reportInputSchema.safeParse(input);
            if (!report.success) {
              response.writeHead(400).end();
              return;
            }
            reports.push(report.data);
            cursor++;
            response.end(JSON.stringify(snapshot()));
          } else {
            const event = BrowserFeedbackEventRequest.safeParse(input);
            if (!event.success) {
              response.writeHead(400).end();
              return;
            }
            if (event.data.type === "reply") replies.push(event.data.text ?? "");
            state = event.data.type === "thread.resolved" ? "resolved" : "open";
            response.end(
              JSON.stringify({
                schema_version: 1,
                cursor: ++cursor,
                feedback_id: id,
                actor: "reviewer",
                type: event.data.type,
                text: event.data.text,
                at: "2026-10-05T00:00:00Z",
              }),
            );
          }
        });
        return;
      }
      if (url.pathname.endsWith("/evidence"))
        response.end(JSON.stringify({ schema_version: 1, failed_requests: [] }));
      else if (url.pathname.endsWith("/events"))
        response.end(JSON.stringify({ schema_version: 1, events: [], event_cursor: cursor }));
      else if (url.pathname.endsWith(id)) response.end(JSON.stringify(snapshot()));
      else
        response.end(
          JSON.stringify({ schema_version: 1, threads: [snapshot()], event_cursor: cursor }),
        );
      return;
    }
    response.setHeader("Content-Type", "text/html");
    response.setHeader(
      "Content-Security-Policy",
      "default-src 'none'; script-src 'nonce-review'; style-src 'nonce-review'; font-src 'self'; connect-src 'self'",
    );
    response.end(
      `<html><head><script type="module" nonce="review" src="/__tnl/feedback/toolbar.fixture.js"></script></head><body><button id="save">${returned ? "Fresh label" : "Save"}</button></body></html>`,
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  let browser: Browser | undefined;
  try {
    browser = await chromium.launch();
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("missing listener");
    const origin = "http://127.0.0.1:" + address.port;
    const page = await browser.newPage();
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.goto(origin + "/preview?tab=review");
    await page.getByRole("button", { name: "Comment", exact: true }).click();
    await page.getByRole("button", { name: "Save", exact: true }).click();
    const draft = page.getByRole("region", { name: "New feedback" });
    await draft
      .getByRole("textbox", { name: "Feedback", exact: true })
      .fill("Keep this report draft");
    expect(await draft.getByRole("button", { name: "send feedback" }).isDisabled()).toBe(true);
    const firstTab = page.context().waitForEvent("page");
    await draft.getByRole("link", { name: /sign in/ }).click();
    const loginTab = await firstTab;
    await loginTab.waitForURL(origin + "/preview?tab=review");
    expect(await loginTab.evaluate(() => window.opener === null)).toBe(true);
    expect(page.url()).toBe(origin + "/preview?tab=review");
    await loginTab.close();
    await page.getByText("signed in as Sam", { exact: true }).waitFor();
    expect(await draft.getByRole("textbox", { name: "Feedback", exact: true }).inputValue()).toBe(
      "Keep this report draft",
    );
    expect(reports).toHaveLength(0);
    await draft.getByRole("button", { name: "send feedback" }).click();
    await expect.poll(() => reports.length).toBe(1);
    expect(reports[0]?.evidence.element?.label).toBe("Save");
    expect(reports[0]?.display_name).toBe("");
    await page.getByRole("heading", { name: "Keep this report draft" }).waitFor();
    await page.getByRole("textbox", { name: "Reply", exact: true }).fill("Keep this reply draft");
    expired = true;
    await page
      .getByText("your sign-in expired; sign in again to leave feedback", { exact: true })
      .waitFor();
    expect(await page.getByRole("button", { name: "Send reply", exact: true }).isDisabled()).toBe(
      true,
    );
    expect(await page.getByRole("button", { name: "Resolve", exact: true }).isDisabled()).toBe(
      true,
    );
    expect(await page.getByRole("heading", { name: "Keep this report draft" }).count()).toBe(1);
    const conversation = page.getByRole("region", { name: "Feedback thread" });
    const secondTab = page.context().waitForEvent("page");
    await conversation.getByRole("link", { name: /sign in/ }).click();
    const renewedTab = await secondTab;
    await renewedTab.waitForURL(origin + "/preview?tab=review");
    expect(await renewedTab.evaluate(() => window.opener === null)).toBe(true);
    expect(page.url()).toBe(origin + "/preview?tab=review");
    await renewedTab.close();
    await page.getByText("signed in as Sam", { exact: true }).waitFor();
    await expect
      .poll(() => page.getByRole("textbox", { name: "Reply", exact: true }).inputValue())
      .toBe("Keep this reply draft");
    expect(replies).toHaveLength(0);
    await page.getByRole("button", { name: "Send reply", exact: true }).click();
    await expect.poll(() => replies).toEqual(["Keep this reply draft"]);
    unavailable = true;
    await expect
      .poll(() => page.getByText("signed in as Sam", { exact: true }).count(), { timeout: 6000 })
      .toBe(0);
    expect(await page.getByRole("button", { name: "Resolve", exact: true }).isDisabled()).toBe(
      true,
    );
    expect(await page.getByRole("heading", { name: "Keep this report draft" }).count()).toBe(1);
    unavailable = false;
    await page.getByText("signed in as Sam", { exact: true }).waitFor();
    required = false;
    await page.getByRole("button", { name: /sign out/ }).click();
    await page
      .getByText("posting anonymously; optional names are unverified", { exact: true })
      .waitFor();
    expect(errors).toEqual([]);
  } finally {
    await browser?.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}, 60_000);
