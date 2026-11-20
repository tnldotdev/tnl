const MINUTE_MS = 60_000;
export const HOST_TURN_MS = 10 * MINUTE_MS;
export const BOOTSTRAP_TURN_MS = 60 * MINUTE_MS;
export const STARTUP_MS = 3 * MINUTE_MS;
export const REPLACE_BEFORE_MS = STARTUP_MS + MINUTE_MS;
export const MAX_HOSTS = 1_000;
// at the three-minute startup bound, a thousand ten-minute turns need about
// 334 overlapping replacements when recruitment starts four minutes early.
export const MAX_STARTING = 384;
export const UPLOAD_BYTES = 1024 * 1024;
export const UPLOAD_MS = 3_000;

export function turnLength(bootstrap: boolean) {
  return bootstrap ? BOOTSTRAP_TURN_MS : HOST_TURN_MS;
}

export function turnLabel(bootstrap: boolean) {
  const minutes = turnLength(bootstrap) / MINUTE_MS;
  return minutes === 60 ? "one hour" : `${minutes} minutes`;
}

export function hostTarget(tabs: number, minimum = 3) {
  return Math.min(MAX_HOSTS, Math.max(minimum, Math.ceil(tabs / 50)));
}
