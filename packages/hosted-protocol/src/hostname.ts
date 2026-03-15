import { toASCII, toUnicode } from "tr46";

export type HostnameErrorCode =
  | "empty"
  | "non_ascii"
  | "invalid_syntax"
  | "ip_literal"
  | "label_too_long"
  | "hostname_too_long"
  | "invalid_alabel"
  | "invalid_port";

export class HostnameError extends Error {
  constructor(readonly code: HostnameErrorCode) {
    super(code);
  }
}

export function canonicalizeHostname(input: string): string {
  if (input.length === 0) throw new HostnameError("empty");
  for (const character of input) {
    if (character.charCodeAt(0) > 0x7f) throw new HostnameError("non_ascii");
  }

  const hostname = (input.endsWith(".") ? input.slice(0, -1) : input).toLowerCase();
  if (hostname.length === 0) throw new HostnameError("empty");
  if (isIPv4(hostname)) throw new HostnameError("ip_literal");
  if (hostname.length > 253) throw new HostnameError("hostname_too_long");

  for (const label of hostname.split(".")) {
    if (label.length === 0 || label.startsWith("-") || label.endsWith("-")) {
      throw new HostnameError("invalid_syntax");
    }
    if (label.length > 63) throw new HostnameError("label_too_long");
    if (!/^[a-z0-9-]+$/.test(label)) throw new HostnameError("invalid_syntax");
    if (label.startsWith("xn--") && !validALabel(label)) {
      throw new HostnameError("invalid_alabel");
    }
  }

  return hostname;
}

export function canonicalizeAuthority(input: string): string {
  if (input.startsWith("[") || isIPv4(input)) throw new HostnameError("ip_literal");

  const parts = input.split(":");
  if (parts.length === 1) return canonicalizeHostname(input);
  if (parts.length !== 2) throw new HostnameError("invalid_syntax");

  const [hostname, port] = parts;
  if (!port || !/^\d+$/.test(port)) throw new HostnameError("invalid_port");
  const portNumber = Number(port);
  if (portNumber < 1 || portNumber > 65535) throw new HostnameError("invalid_port");
  return canonicalizeHostname(hostname ?? "");
}

function isIPv4(value: string): boolean {
  const parts = value.split(".");
  return (
    parts.length === 4 &&
    parts.every((part) => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255)
  );
}

function validALabel(label: string): boolean {
  const options = {
    checkBidi: true,
    checkHyphens: true,
    checkJoiners: true,
    ignoreInvalidPunycode: false,
    transitionalProcessing: false,
    useSTD3ASCIIRules: true,
  };
  const decoded = toUnicode(label, options);
  if (decoded.error || decoded.domain === label) return false;
  return toASCII(decoded.domain, { ...options, verifyDNSLength: true }) === label;
}
