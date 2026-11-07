export function GET(request: Request) {
  return Response.json({
    source: request.headers.get("x-forwarded-for"),
    credential: request.headers.get("x-tnl-proxy-token"),
  });
}
