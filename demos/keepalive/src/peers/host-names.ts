import * as z from "zod/mini";
import { first, second } from "./host-words.ts";

const firstWords = new Set(first);
const secondWords = new Set(second);
const storageKey = "keepalive.host-name";
export const hostNameSchema = z.string().check(
  z.maxLength(20),
  z.regex(/^[a-z]+-[a-z]+$/),
  z.refine((name) => {
    const [left, right] = name.split("-");
    return firstWords.has(left ?? "") && secondWords.has(right ?? "");
  }),
);

export function browserHostName() {
  const left = first[Math.floor(Math.random() * first.length)] ?? "quiet";
  const right = second[Math.floor(Math.random() * second.length)] ?? "pine";
  const fresh = `${left}-${right}`;
  try {
    const saved = hostNameSchema.safeParse(localStorage.getItem(storageKey));
    if (saved.success) return saved.data;
    localStorage.setItem(storageKey, fresh);
  } catch {
    // restricted storage shouldn't prevent a tab from hosting.
  }
  return fresh;
}
