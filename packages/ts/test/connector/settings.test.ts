import { expect, test, vi } from "vitest";
import { decodeSettings, settingsDecoders } from "../../src/internal/connector/settings.js";

const decoders = settingsDecoders({
  http: () => async () => new Response("owned HTTP"),
  mysql: () => () => {
    throw new Error("must not dial during decoder tests");
  },
});
const postgres = {
  schema: 1,
  protocol: "postgres",
  host: "127.0.0.1",
  port: 15432,
  ssl: { servername: "db.example", rejectUnauthorized: true },
  transport_id: `ctg_${"a".repeat(22)}`,
  expires_at: new Date(Date.now() + 60_000).toISOString(),
};

test.each([
  { ...postgres, protocol: "http", url: "https://db.example" },
  { ...postgres, host: "other.internal" },
  { ...postgres, expires_at: new Date(0).toISOString() },
  { ...postgres, transport_id: "missing" },
  { ...postgres, ssl: { ...postgres.ssl, rejectUnauthorized: false } },
  { ...postgres, ssl: { ...postgres.ssl, key: "private" } },
  { ...postgres, ssl: { ...postgres.ssl, cert: "private" } },
  { ...postgres, password: "application-owned" },
])("a narrow PostgreSQL decoder validates unknown native input (%j)", (input) => {
  expect(() => decodeSettings(decoders, "postgres", input)).toThrow(
    expect.objectContaining({ code: "sdk.response_invalid" }),
  );
});

test("a wrong protocol cannot construct transport functions", () => {
  const http = vi.fn(() => async () => new Response("unused"));
  const owned = settingsDecoders({
    http,
    mysql: () => () => {
      throw new Error("unused");
    },
  });
  expect(() => decodeSettings(owned, "http", postgres)).toThrow(
    expect.objectContaining({ code: "sdk.response_invalid" }),
  );
  expect(http).not.toHaveBeenCalled();
});
