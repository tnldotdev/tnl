import { turnLabel } from "../src/policy.ts";

export function startPage(index: string, site: string) {
  return index
    .replace('id="app"', 'id="app" data-start')
    .replace("<h1>can we keep this alive?</h1>", "<h1>start keepalive</h1>")
    .replace(
      /<p id="introduction">[\s\S]*?<\/p>/,
      `<p id="introduction">Start the first host for <a href="https://${site}">${site}</a> for up to ${turnLabel(true)}. Keep this tab open to keep the site online.</p>`,
    );
}
