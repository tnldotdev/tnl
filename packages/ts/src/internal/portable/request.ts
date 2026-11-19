const wrappedRequests = new WeakSet<Request>();

// go supplies a genuine Request with raw headers attached: browser Request
// construction otherwise filters Cookie. native clone tees the body but copies
// only internal filtered headers, so carry the raw headers onto every clone.
// this cannot recover headers already lost by an ordinary Request constructor.
export function preserveRequestHeaders(request: Request): Request {
  if (wrappedRequests.has(request)) return request;
  const headers = request.headers;
  const nativeClone = request.clone;
  Object.defineProperty(request, "clone", {
    value: () => {
      const copy = nativeClone.call(request);
      Object.defineProperty(copy, "headers", { value: new Headers(headers) });
      return preserveRequestHeaders(copy);
    },
  });
  wrappedRequests.add(request);
  return request;
}
