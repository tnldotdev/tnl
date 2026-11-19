import * as z from "zod";

const first = ["quiet", "silver", "still", "soft", "early", "bright", "clear", "small"];
const second = [
  "pine",
  "birch",
  "water",
  "fern",
  "moss",
  "dawn",
  "cloud",
  "stone",
  "brook",
  "reed",
];
const names = first.flatMap((left) => second.map((right) => `${left}-${right}`));
const allowed = new Set(names);
const storageKey = "keepalive.host-name";
export const hostNameSchema = z
  .string()
  .max(20)
  .refine((name) => allowed.has(name));

export function browserHostName() {
  const fresh = names[Math.floor(Math.random() * names.length)] ?? "quiet-pine";
  try {
    const saved = hostNameSchema.safeParse(localStorage.getItem(storageKey));
    if (saved.success) return saved.data;
    localStorage.setItem(storageKey, fresh);
  } catch {
    // restricted storage shouldn't prevent a tab from hosting.
  }
  return fresh;
}
