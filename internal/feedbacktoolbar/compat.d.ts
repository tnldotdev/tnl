import type { Context } from "preact";
import "preact/compat";

declare module "preact/compat" {
  // react-query names the provider type; preact exposes it through Context.
  export type Provider<T> = Context<T>["Provider"];
}
