// compatibility adapter for the served Vite client (6/7/8), not a tnl runtime assertion.
// Vite doesn't expose the browser WebSocket token through a public client API.
export function viteClientConnection(client: string): { environmentPath: string; token: string } {
  const environment = client.match(/\bimport\s*(["'])(\/[^"']*\/env\.mjs(?:\?[^"']*)?)\1/);
  const token = client.match(/\b(?:const|let|var)\s+wsToken\s*=\s*(["'])([^"']+)\1/);
  if (environment?.[2] === undefined || token?.[2] === undefined) {
    throw new Error(
      "Unsupported Vite client: expected an env.mjs import and wsToken; update the test compatibility adapter",
    );
  }
  return { environmentPath: environment[2], token: token[2] };
}
