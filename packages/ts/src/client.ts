/** standard fetch calls, independent of runtime-specific static helpers. */
export type TnlFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export type TnlHTTPConnection = Readonly<{ url: `https://${string}`; fetch: TnlFetch }>;

/** callbacks adapt ordinary clients without adding a driver-specific wrapper. */
export type TnlClientOptions<Connection, Client> = Readonly<{
  create(connection: Connection): Client | PromiseLike<Client>;
  close(client: Client): void | PromiseLike<void>;
}>;

export type TnlClientFactory<Client> = {
  (): Promise<Client>;
  close(): Promise<void>;
};
