export function GET(request: Request) {
  const token = process.env.TNL_APP_PROXY_TOKEN;
  return Response.json({
    available: typeof token === "string" && /^[a-f0-9]{64}$/.test(token),
    matches: request.headers.get("x-tnl-proxy-token") === token,
  });
}
