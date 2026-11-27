// observation-only until calibration and live comparisons establish the fixed
// per-host budget. do not feed internal maintenance traffic back into demand.
export function capacityTarget({
  readerBytesPerSecond,
  safeBytesPerSecondPerHost,
  countedReaderLeases,
}: {
  readerBytesPerSecond: number;
  safeBytesPerSecondPerHost: number;
  countedReaderLeases: number;
}) {
  if (
    !Number.isFinite(readerBytesPerSecond) ||
    readerBytesPerSecond < 0 ||
    !Number.isFinite(safeBytesPerSecondPerHost) ||
    safeBytesPerSecondPerHost <= 0 ||
    !Number.isSafeInteger(countedReaderLeases) ||
    countedReaderLeases < 0
  )
    throw new Error("recruitment needs fresh, finite demand and a calibrated positive budget");
  return Math.max(
    3,
    Math.ceil(readerBytesPerSecond / safeBytesPerSecondPerHost),
    Math.ceil(countedReaderLeases / 256),
  );
}

export function recruitmentDeficit({
  needed,
  readyBeyondReplacementWindow,
  starting,
}: {
  needed: number;
  readyBeyondReplacementWindow: number;
  starting: number;
}) {
  for (const value of [needed, readyBeyondReplacementWindow, starting])
    if (!Number.isSafeInteger(value) || value < 0) throw new Error("invalid recruitment capacity");
  return Math.max(0, needed - readyBeyondReplacementWindow - starting);
}
