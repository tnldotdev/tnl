const MINUTE_MS = 60_000;
export const HOST_TURN_MS = 10 * MINUTE_MS;
export const BOOTSTRAP_TURN_MS = 60 * MINUTE_MS;
export const REPLACE_BEFORE_MS = 2 * MINUTE_MS;
export const STARTUP_MS = 115_000;
export const UPLOAD_BYTES = 1024 * 1024;
export const UPLOAD_MS = 3_000;

export function turnLength(bootstrap: boolean) {
  return bootstrap ? BOOTSTRAP_TURN_MS : HOST_TURN_MS;
}

export function turnLabel(bootstrap: boolean) {
  const minutes = turnLength(bootstrap) / MINUTE_MS;
  return minutes === 60 ? "one hour" : `${minutes} minutes`;
}

export function hostTarget(tabs: number) {
  return Math.max(3, Math.ceil(tabs / 50));
}
