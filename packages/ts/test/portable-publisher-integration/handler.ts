import { check } from "./fixture.ts";

// all calls enter this handler through the real go service owner. there is no
// replacement publisher, relay, authorization backend, or local HTTP listener.
export function publisherHandler(runtime: string) {
  let release: (() => void) | undefined;
  let canceled = false;
  let requestAborted = false;
  let calls = 0;
  const encoder = new TextEncoder();
  const handle = async (request: Request): Promise<Response> => {
    calls++;
    const path = new URL(request.url).pathname;
    check(request.headers.get("Tnl-Access-Token") === null, "visitor credential reached handler");
    if (path === "/evidence") return Response.json({ canceled, requestAborted, calls });
    if (path === "/release") {
      check(release !== undefined, "response was not streaming before release");
      release();
      return new Response("released");
    }
    if (path === "/echo")
      return new Response(request.body, {
        headers: { "Content-Type": "application/octet-stream" },
      });
    if (path === "/stream") {
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          release = () => {
            controller.enqueue(encoder.encode("last\n"));
            controller.close();
          };
          controller.enqueue(encoder.encode("first\n"));
        },
      });
      return new Response(body, { headers: { "Content-Type": "application/octet-stream" } });
    }
    if (path === "/cancel") {
      canceled = false;
      requestAborted = false;
      request.signal.addEventListener(
        "abort",
        () => {
          requestAborted = true;
        },
        { once: true },
      );
      return new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(encoder.encode("cancel-ready\n"));
          },
          cancel() {
            canceled = true;
          },
        }),
        { headers: { "Content-Type": "application/octet-stream" } },
      );
    }
    return new Response("portable-publisher", { headers: { "X-Publisher-Runtime": runtime } });
  };
  return { handle, calls: () => calls };
}
