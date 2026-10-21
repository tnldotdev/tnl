import { AsyncLocalStorage } from "node:async_hooks";
import {
  context,
  trace,
  ROOT_CONTEXT,
  SpanStatusCode,
  isSpanContextValid,
  createContextKey,
  type Context,
  type Link,
  type SpanOptions,
} from "@opentelemetry/api";

// use the host's OTel provider without installing globals or exporters. local
// async scope also carries native launch parents when the host has no manager.
const local = new AsyncLocalStorage<Context>();
const tracer = trace.getTracer("@tnldotdev/tnl");
const schedulingLinks = createContextKey("tnl scheduling links");
type Operation =
  | "sdk.prepare"
  | "sdk.connect"
  | "sdk.connect.read"
  | "sdk.open"
  | "sdk.app.register"
  | "sdk.app.renew"
  | "sdk.app.recover"
  | "sdk.app.cleanup"
  | "sdk.open.recover"
  | "sdk.open.renew"
  | "sdk.open.status"
  | "sdk.open.cleanup"
  | "sdk.native.command"
  | "sdk.native.request"
  | "vite.prepare"
  | "vite.register"
  | "vite.restart"
  | "vite.cleanup"
  | "next.register"
  | "next.restart"
  | "next.cleanup";

function options(name: Operation, parent: Context): SpanOptions {
  const links =
    trace.getSpanContext(parent) === undefined
      ? (parent.getValue(schedulingLinks) as Link[] | undefined)
      : undefined;
  return {
    attributes: { "tnl.operation": name, "tnl.component": "client" },
    ...(links === undefined ? {} : { links }),
  };
}

function active(): Context {
  return local.getStore() ?? context.active();
}

function runContext<T>(scope: Context, work: () => T): T {
  return local.run(scope, () => context.with(scope, work));
}

export function traceparent(): string | undefined {
  const sc = trace.getSpanContext(active());
  if (sc === undefined || !isSpanContextValid(sc)) return undefined;
  return `00-${sc.traceId}-${sc.spanId}-${(sc.traceFlags & 1) === 1 ? "01" : "00"}`;
}

export function launchEnvironment(): NodeJS.ProcessEnv {
  const environment = { ...process.env };
  delete environment.TNL_TRACEPARENT;
  const parent = traceparent();
  if (parent !== undefined) environment.TNL_TRACEPARENT = parent;
  return environment;
}

export function traceHeaders(): Readonly<Record<string, string>> {
  const parent = traceparent();
  return parent === undefined ? {} : { traceparent: parent };
}

export async function operation<T>(name: Operation, work: () => Promise<T>): Promise<T> {
  const parent = active();
  const span = tracer.startSpan(name, options(name, parent), parent);
  return runContext(trace.setSpan(parent, span), async () => {
    try {
      const result = await work();
      span.setAttribute("tnl.outcome", "success");
      return result;
    } catch (cause) {
      span.setAttribute("tnl.outcome", "error");
      span.setStatus({ code: SpanStatusCode.ERROR, message: "error" });
      throw cause;
    } finally {
      span.end();
    }
  });
}

export function operationSync<T>(name: Operation, work: () => T): T {
  const parent = active();
  const span = tracer.startSpan(name, options(name, parent), parent);
  return runContext(trace.setSpan(parent, span), () => {
    try {
      const result = work();
      span.setAttribute("tnl.outcome", "success");
      return result;
    } catch (cause) {
      span.setAttribute("tnl.outcome", "error");
      span.setStatus({ code: SpanStatusCode.ERROR, message: "error" });
      throw cause;
    } finally {
      span.end();
    }
  });
}

// scheduled work retains only a bounded causal link. it does not retain a
// request's context, baggage, tracestate, or authenticated application values.
export function independent<T>(name: Operation, work: () => Promise<T>): () => Promise<T> {
  return scheduled(() => operation(name, work));
}

export function scheduled<T>(work: () => T): () => T {
  const sc = trace.getSpanContext(active());
  const links: Link[] =
    sc === undefined || !isSpanContextValid(sc)
      ? []
      : [{ context: { traceId: sc.traceId, spanId: sc.spanId, traceFlags: sc.traceFlags } }];
  const root = ROOT_CONTEXT.setValue(schedulingLinks, links);
  return () => runContext(root, work);
}

export function background<T>(work: () => T): T {
  return runContext(ROOT_CONTEXT, work);
}

export function bound(): void {
  trace.getSpan(active())?.addEvent("bound", { "tnl.event": "bound" });
}
