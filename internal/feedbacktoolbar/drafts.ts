import { z } from "zod";
import { anchorSchema, type Anchor } from "./model.ts";
import { captureElement } from "./evidence.ts";
import { restoreAnchor, type AnchorTarget } from "./anchors.ts";

const storageKey = "tnl.feedback.unsent.v1";
const lifetime = 15 * 60_000;
const text = z.string().refine((value) => new TextEncoder().encode(value).length <= 4000);
const report = z.strictObject({
  mode: z.literal("report"),
  text,
  name: z.string().refine((value) => new TextEncoder().encode(value).length <= 64),
  activity: z.boolean(),
  anchor: anchorSchema.optional(),
  uncertain: z.boolean(),
});
const thread = z.strictObject({
  mode: z.literal("thread"),
  text,
  id: z.string().regex(/^fb_[A-Za-z0-9]{22}$/),
  uncertain: z.boolean(),
});
const schema = z.strictObject({
  version: z.literal(1),
  url: z.string().max(4096),
  expires: z.number().int(),
  draft: z.discriminatedUnion("mode", [report, thread]),
});
export type Recovery = z.infer<typeof schema>["draft"];
export type ReportDraft = z.infer<typeof report>;
export type ThreadDraft = z.infer<typeof thread>;

function pageURL(document: Document): string {
  return document.location.origin + document.location.pathname + document.location.search;
}

export function saveDraft(
  document: Document,
  draft: Recovery | undefined,
  now = Date.now(),
): boolean {
  try {
    const storage = document.defaultView?.sessionStorage;
    if (!storage) return false;
    if (!draft) {
      storage.removeItem(storageKey);
      return true;
    }
    const value = schema.parse({
      version: 1,
      url: pageURL(document),
      expires: now + lifetime,
      draft,
    });
    const raw = JSON.stringify(value);
    if (new TextEncoder().encode(raw).length > 16 << 10) return false;
    storage.setItem(storageKey, raw);
    return true;
  } catch {
    return false;
  }
}

export function restoreDraft(document: Document, now = Date.now()): Recovery | undefined {
  try {
    const storage = document.defaultView?.sessionStorage;
    const raw = storage?.getItem(storageKey);
    if (!raw) return undefined;
    storage?.removeItem(storageKey);
    if (new TextEncoder().encode(raw).length > 16 << 10) return undefined;
    const value = schema.safeParse(JSON.parse(raw) as unknown);
    if (
      !value.success ||
      value.data.url !== pageURL(document) ||
      value.data.expires <= now ||
      value.data.expires > now + lifetime
    )
      return undefined;
    return value.data.draft;
  } catch {
    return undefined;
  }
}

// evidence is captured afresh; changed text selections and missing elements are
// restored as page comments rather than reusing stale HTML or selection context.
export function recoverTarget(
  document: Document,
  anchor: Anchor | undefined,
): AnchorTarget | undefined {
  if (!anchor) return undefined;
  const restored = restoreAnchor(document, anchor);
  return restored && !restored.textChanged
    ? { anchor, element: captureElement(restored.element) }
    : undefined;
}
