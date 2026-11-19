import * as z from "zod";
import { readJSON } from "./release.ts";

export const NETWORK_PROOF_PATH = "/__keepalive/network-proof";
export const NETWORK_CHECK_PATH = "/__keepalive/network-check";
export const networkProof = z.string().regex(/^[a-f0-9]{64}\.\d{13}\.[a-f0-9]{64}$/);
const comparison = z.strictObject({ host: networkProof, volunteer: networkProof });
const encoder = new TextEncoder();
const algorithm = { name: "HMAC", hash: "SHA-256" };
// cover bootstrap startup and its hour-long turn.
const NETWORK_PROOF_MS = 70 * 60_000;

const importKey = (secret: string) =>
  crypto.subtle.importKey("raw", encoder.encode(secret), algorithm, false, ["sign", "verify"]);
const mac = async (key: CryptoKey, text: string) =>
  Array.from(new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(text))), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");

const ipAddress = z.union([z.ipv4(), z.ipv6()]);

/**
 * turns the public IP seen by the proxy into a short-lived proof. the proxy can
 * compare two proofs to check for the same IP without sharing either address.
 */
export async function proveNetwork(ip: string, secret: string) {
  const key = await importKey(secret);
  const address = ipAddress.parse(ip);
  const canonical = address.includes(":") ? new URL(`http://[${address}]`).hostname : address;
  const label = await mac(key, `ip:${canonical}`);
  const expiresAt = Date.now() + NETWORK_PROOF_MS;
  const body = `${label}.${expiresAt}`;
  return `${body}.${await mac(key, `proof:${body}`)}`;
}

export async function compareNetworks(request: Request, secret: string) {
  const body = comparison.parse(await readJSON(new Response(request.body), 512, request.signal));
  const key = await importKey(secret);
  async function verifiedLabel(proof: string) {
    const [label, expiresAt, signature] = proof.split(".");
    if (label === undefined || expiresAt === undefined || signature === undefined) return;
    if (Number(expiresAt) <= Date.now()) return;
    const bytes = Uint8Array.from(signature.match(/../g) ?? [], (pair) =>
      Number.parseInt(pair, 16),
    );
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      bytes,
      encoder.encode(`proof:${label}.${expiresAt}`),
    );
    return valid ? label : undefined;
  }
  const host = await verifiedLabel(body.host);
  const volunteer = await verifiedLabel(body.volunteer);
  return host !== undefined && volunteer !== undefined && host !== volunteer;
}
