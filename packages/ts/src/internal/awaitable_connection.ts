import type { TnlConnectionHandle } from "../project.js";

/** one enumeration uses one snapshot, even if the owner rotates between reads. */
export function awaitableConnection<Settings extends object>(
  read: () => Settings,
  prepare: () => Promise<Settings>,
): TnlConnectionHandle<Settings> {
  const target = Object.create(null) as object;
  const then: PromiseLike<Settings>["then"] = (fulfilled, rejected) =>
    prepare().then(fulfilled, rejected);
  // oxlint-disable-next-line unicorn/no-thenable -- the public handle intentionally implements PromiseLike.
  Object.defineProperty(target, "then", { value: then, enumerable: false });
  let enumeration: Settings | undefined;
  let remaining = new Set<PropertyKey>();
  return new Proxy(target, {
    get(_target, key) {
      if (key === "then") return then;
      if (typeof key !== "string" || key === "toJSON") return undefined;
      const snapshot = enumeration ?? read();
      const value: unknown = Reflect.get(snapshot, key);
      remaining.delete(key);
      if (remaining.size === 0) enumeration = undefined;
      return value;
    },
    has(_target, key) {
      if (key === "then") return true;
      return Object.hasOwn(enumeration ?? read(), key);
    },
    ownKeys() {
      const snapshot = read();
      enumeration = snapshot;
      const keys = Reflect.ownKeys(snapshot);
      remaining = new Set(keys);
      queueMicrotask(() => {
        if (enumeration === snapshot) enumeration = undefined;
      });
      return [...keys, "then"];
    },
    getOwnPropertyDescriptor(_target, key) {
      if (key === "then") return Reflect.getOwnPropertyDescriptor(target, key);
      const snapshot = enumeration ?? read();
      const descriptor = Reflect.getOwnPropertyDescriptor(snapshot, key);
      return descriptor === undefined ? undefined : { ...descriptor, configurable: true };
    },
    set: () => false,
    defineProperty: () => false,
    deleteProperty: () => false,
    setPrototypeOf: () => false,
    preventExtensions: () => false,
  }) as TnlConnectionHandle<Settings>;
}
