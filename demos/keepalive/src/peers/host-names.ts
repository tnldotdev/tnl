import * as z from "zod";
import words from "../../../../internal/naming/corpus/friendly-words.json" with { type: "json" };

const first = words.predicates.filter((word) => word.length <= 9);
const second = words.objects.filter((word) => word.length <= 10);
const firstWords = new Set(first);
const secondWords = new Set(second);
const storageKey = "keepalive.host-name";
export const hostNameSchema = z
  .string()
  .max(20)
  .regex(/^[a-z]+-[a-z]+$/)
  .refine((name) => {
    const [left, right] = name.split("-");
    return firstWords.has(left ?? "") && secondWords.has(right ?? "");
  });

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
