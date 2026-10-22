// a user retry retains the exact body and key, even if the response was lost.
export function mutationKey() {
  let previous = "";
  let key = "";
  return (body: unknown): string => {
    const identity = JSON.stringify(body);
    if (identity !== previous) {
      previous = identity;
      key = crypto.randomUUID();
    }
    return key;
  };
}
