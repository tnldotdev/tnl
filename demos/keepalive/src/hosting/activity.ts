export const PULSE_SECONDS = 30;

const secondAt = (now: number) => Math.floor(now / 1_000);

export class RequestActivity {
  #count = 0;
  readonly #seconds = new Set<number>();

  get count() {
    return this.#count;
  }

  record(response: Response, now: number) {
    if (!response.ok) return;
    this.#count++;
    const second = secondAt(now);
    this.#prune(second);
    this.#seconds.add(second);
  }

  snapshot(now: number) {
    const second = secondAt(now);
    this.#prune(second);
    let pulse = "";
    for (let offset = PULSE_SECONDS - 1; offset >= 0; offset--)
      pulse += this.#seconds.has(second - offset) ? "|" : "_";
    return { second, pulse, requests: this.#count };
  }

  #prune(second: number) {
    for (const previous of this.#seconds)
      if (previous <= second - PULSE_SECONDS || previous > second) this.#seconds.delete(previous);
  }
}

export function requestPulse(pulse: string, second: number, now: number) {
  const elapsed = Math.min(PULSE_SECONDS, Math.max(0, secondAt(now) - second));
  return pulse.slice(elapsed) + "_".repeat(elapsed);
}
