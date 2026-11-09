import { createTnl } from "@tnldotdev/tnl/web";

export function application(env: { readonly TNL_CREDENTIAL: string }) {
  const app = createTnl({ credential: env.TNL_CREDENTIAL });
  const api = app.connect("https://app.example");
  const get = app.client("https://app.example", {
    create: (connection) => ({ fetch: connection.fetch }),
    close: async () => {},
  });
  return {
    async fetch(): Promise<Response> {
      return (await get()).fetch("/stock");
    },
    async close(): Promise<void> {
      await app.close();
    },
    settings: api,
  };
}
