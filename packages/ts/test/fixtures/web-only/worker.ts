import {
  createTnl,
  type TnlApplicationCredential,
  type TnlApplicationResource,
} from "@tnldotdev/tnl/web";

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

export async function preparedApplication(
  credential: TnlApplicationCredential,
  resource: TnlApplicationResource,
) {
  const app = createTnl({ credential });
  const api = await app.connect(resource);
  const get = app.client(resource, {
    create: (connection) => ({ fetch: connection.fetch }),
    close: async () => {},
  });
  return { api, get, close: () => app.close() };
}
