declare namespace JSX {
  type Element = HTMLElement;
  interface IntrinsicElements {
    [tag: string]: Record<string, unknown>;
  }
}
