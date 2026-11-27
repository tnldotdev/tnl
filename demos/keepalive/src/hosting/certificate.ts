import type { ExportedCertificate } from "@tnldotdev/tnl";
import * as z from "zod/mini";
import { STARTUP_MS, turnLength } from "../policy.ts";
import { digest, readJSON } from "../release.ts";

export const CERTIFICATE_PATH = "/__keepalive/certificate";
export const CERTIFICATE_PROOF_PATH = "/__keepalive/certificate-proof";
export const CERTIFICATE_BYTES = 160 * 1024;
const CLOCK_MARGIN_MS = 30_000;
const RENEW_MS = 24 * 60 * 60_000;

export const certificateBundle = z.strictObject({
  certificate: z.strictObject({
    certificatePEM: z.string().check(z.minLength(1), z.maxLength(131072)),
    privateKeyPEM: z.string().check(z.minLength(1), z.maxLength(16384)),
  }),
  expiresAt: z.int().check(z.positive()),
});
export const inheritedCertificate = z.strictObject({
  bundle: certificateBundle,
  knownHosts: z.int().check(z.positive()),
});
export const certificateReport = z.strictObject({
  fingerprint: z.string().check(z.regex(/^[a-f0-9]{64}$/)),
  expiresAt: z.int().check(z.positive()),
});
export type CertificateReport = z.infer<typeof certificateReport>;

export function newerCertificate(candidate: CertificateReport, current: CertificateReport) {
  return (
    candidate.expiresAt > current.expiresAt ||
    (candidate.expiresAt === current.expiresAt && candidate.fingerprint < current.fingerprint)
  );
}

export function chooseCertificate(
  inherited: z.infer<typeof inheritedCertificate> | undefined,
  bootstrap: boolean,
  now: number,
  random = Math.random,
): ExportedCertificate | undefined {
  if (bootstrap || inherited === undefined) return undefined;
  const { bundle, knownHosts } = inherited;
  if (bundle.expiresAt - now <= turnLength(false) + STARTUP_MS + CLOCK_MARGIN_MS) return undefined;
  if (bundle.expiresAt - now <= RENEW_MS && random() < 1 / Math.max(1, knownHosts))
    return undefined;
  return bundle;
}

export async function describeCertificate(bundle: ExportedCertificate) {
  const leaf = /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/.exec(
    bundle.certificate.certificatePEM,
  )?.[1];
  if (leaf === undefined) throw new Error("Could not read the installed service certificate.");
  const bytes = Uint8Array.from(atob(leaf.replaceAll(/\s/g, "")), (byte) => byte.charCodeAt(0));
  return { expiresAt: bundle.expiresAt, fingerprint: await digest(bytes) };
}

export async function readInheritedCertificate(response: Response, signal: AbortSignal) {
  return inheritedCertificate.parse(await readJSON(response, CERTIFICATE_BYTES, signal));
}
