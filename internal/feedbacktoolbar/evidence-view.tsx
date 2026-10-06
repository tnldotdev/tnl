import type { Evidence } from "./model.ts";

export function EvidenceView({ evidence }: { evidence: Evidence }) {
  return (
    <details class="context">
      <summary>
        context
        {evidence.failed_requests.length
          ? ` · ${evidence.failed_requests.length} failed request${evidence.failed_requests.length === 1 ? "" : "s"}`
          : ""}
      </summary>
      {evidence.element && (
        <p class="muted">
          {evidence.element.role ?? "element"}
          {evidence.element.label ? ` · ${evidence.element.label}` : ""}
        </p>
      )}
      {!!evidence.actions.length && (
        <>
          <small>recent activity</small>
          <ul>
            {evidence.actions.map((action, index) => (
              <li key={index}>
                {action.type}
                {action.label ? ` · ${action.label}` : action.path ? ` · ${action.path}` : ""}
              </li>
            ))}
          </ul>
        </>
      )}
      {!!evidence.failed_requests.length && (
        <>
          <small>failed requests</small>
          <ul>
            {evidence.failed_requests.map((request, index) => (
              <li key={index}>
                {request.method} {request.path}{" "}
                <span class="muted">
                  {request.status || "connection failed"} · {request.duration_ms}ms
                </span>
              </li>
            ))}
          </ul>
        </>
      )}
      {!evidence.actions.length && !evidence.failed_requests.length && (
        <p class="muted">no activity included</p>
      )}
    </details>
  );
}
