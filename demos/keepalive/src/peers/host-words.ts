import words from "../../../../internal/naming/corpus/friendly-words.json" with { type: "json" };

export const first = words.predicates.filter((word) => word.length <= 9);
export const second = words.objects.filter((word) => word.length <= 10);
