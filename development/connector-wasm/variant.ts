export const variants = ["baseline", "buffers", "promises", "optimized"] as const;
export type Variant = (typeof variants)[number];

export function parseVariant(value: string | undefined | null): Variant {
  const found = variants.find((variant) => variant === (value ?? "baseline"));
  if (!found) throw new Error("variant must be baseline, buffers, promises, or optimized");
  return found;
}

export function tuning(variant: Variant): { reuseBuffers: boolean; compactPromises: boolean } {
  return {
    reuseBuffers: variant === "buffers" || variant === "optimized",
    compactPromises: variant === "promises" || variant === "optimized",
  };
}
