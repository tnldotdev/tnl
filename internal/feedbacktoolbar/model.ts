export type Pin = {
  kind: "page" | "element";
  role?: string | undefined;
  label?: string | undefined;
  test_id?: string | undefined;
  html?: string | undefined;
};

export type FeedbackSummary = {
  id: string;
  state: "open" | "ready_for_recheck" | "resolved";
  report: { text: string; created_at: string };
  element: Pin;
};

export type FailedRequest = { method: string; path: string; status: number; duration_ms: number };
export type Action = {
  type: "navigation" | "click" | "submit";
  path?: string | undefined;
  label?: string | undefined;
  test_id?: string | undefined;
};
export type FeedbackEvent = { cursor: number; type: string; at: string; text?: string | undefined };

export function record(value: unknown): Record<string, unknown> | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

export function parseSummaries(value: unknown): FeedbackSummary[] {
  const body = record(value);
  if (!Array.isArray(body?.threads)) return [];
  const result: FeedbackSummary[] = [];
  for (const item of body.threads) {
    const entry = record(item);
    const report = record(entry?.report);
    const element = record(entry?.element);
    if (
      typeof entry?.id !== "string" ||
      typeof report?.text !== "string" ||
      typeof report.created_at !== "string" ||
      (entry.state !== "open" &&
        entry.state !== "ready_for_recheck" &&
        entry.state !== "resolved") ||
      (element?.kind !== "page" && element?.kind !== "element")
    )
      continue;
    result.push({
      id: entry.id,
      state: entry.state,
      report: { text: report.text, created_at: report.created_at },
      element: {
        kind: element.kind,
        role: typeof element.role === "string" ? element.role : undefined,
        label: typeof element.label === "string" ? element.label : undefined,
        test_id: typeof element.test_id === "string" ? element.test_id : undefined,
      },
    });
  }
  return result;
}

export function parseFailedRequests(value: unknown): FailedRequest[] {
  const body = record(value);
  if (!Array.isArray(body?.failed_requests)) return [];
  const result: FailedRequest[] = [];
  for (const item of body.failed_requests.slice(0, 20)) {
    const entry = record(item);
    if (
      typeof entry?.method === "string" &&
      typeof entry.path === "string" &&
      typeof entry.status === "number" &&
      typeof entry.duration_ms === "number"
    ) {
      result.push({
        method: entry.method,
        path: entry.path,
        status: entry.status,
        duration_ms: entry.duration_ms,
      });
    }
  }
  return result;
}

export function parseEvents(value: unknown): FeedbackEvent[] {
  const body = record(value);
  if (!Array.isArray(body?.events)) return [];
  const events: FeedbackEvent[] = [];
  for (const item of body.events) {
    const event = record(item);
    if (
      typeof event?.cursor === "number" &&
      typeof event.type === "string" &&
      typeof event.at === "string"
    ) {
      events.push({
        cursor: event.cursor,
        type: event.type,
        at: event.at,
        text: typeof event.text === "string" ? event.text : undefined,
      });
    }
  }
  return events;
}
