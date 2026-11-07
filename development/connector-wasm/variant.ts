export const variants = [
  "baseline",
  "buffers",
  "promises",
  "optimized",
  "application-pump",
  "socket-pump",
  "streaming",
] as const;
export type Variant = (typeof variants)[number];

export function parseVariant(value: string | undefined | null): Variant {
  const found = variants.find((variant) => variant === (value ?? "baseline"));
  if (!found) throw new Error(`variant must be one of ${variants.join(", ")}`);
  return found;
}

export function tuning(variant: Variant): {
  reuseBuffers: boolean;
  compactPromises: boolean;
  applicationPump: boolean;
  socketPump: boolean;
} {
  const pumped =
    variant === "application-pump" || variant === "socket-pump" || variant === "streaming";
  return {
    reuseBuffers: variant === "buffers" || variant === "optimized" || pumped,
    compactPromises: variant === "promises" || variant === "optimized" || pumped,
    applicationPump: variant === "application-pump" || variant === "streaming",
    socketPump: variant === "socket-pump" || variant === "streaming",
  };
}
