// browser Response construction filters Set-Cookie. publishers must opt into
// this helper when their handler needs raw response headers, including cookies.
// it remains a real Response; only its headers and clone method are attached.
export function response(body?: BodyInit | null, init?: ResponseInit): Response {
  const headers = new Headers(init?.headers);
  // dictionary members may be inherited getters, including on a Response.
  const status = init?.status;
  const statusText = init?.statusText;
  const settings: ResponseInit = { headers };
  if (status !== undefined) settings.status = status;
  if (statusText !== undefined) settings.statusText = statusText;
  const constructed = new Response(body, settings);
  // preserve body-derived headers, especially the exact multipart boundary.
  // raw caller headers remain authoritative, including browser-filtered cookies.
  for (const [name, value] of constructed.headers)
    if (!headers.has(name)) headers.append(name, value);
  return withRawHeaders(constructed, headers);
}

function withRawHeaders(value: Response, headers: Headers): Response {
  const nativeClone = value.clone;
  Object.defineProperties(value, {
    headers: {
      get: () => headers,
      enumerable: true,
    },
    clone: {
      value: () => withRawHeaders(nativeClone.call(value), new Headers(headers)),
    },
  });
  return value;
}
