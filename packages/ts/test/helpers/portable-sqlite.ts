import { DatabaseSync } from "node:sqlite";
import type {
  PublisherSQLiteStorage,
  PublisherSQLiteValue,
} from "../../src/internal/portable/storage-durable-object.js";
import type { DurableObjectPublisherState } from "../../src/durable-object.js";

// real sqlite statements with the attached-storage api's blob return shape.
// this fixture proves storage and owner boundaries, not workerd or deployment.
export function portableSQLite(filename = ":memory:") {
  const database = new DatabaseSync(filename);
  const sql: PublisherSQLiteStorage["sql"] = {
    exec<T extends Record<string, PublisherSQLiteValue>>(
      query: string,
      ...bindings: PublisherSQLiteValue[]
    ) {
      const rows = database
        .prepare(query)
        .all(
          ...bindings.map((value) =>
            value instanceof ArrayBuffer ? new Uint8Array(value) : value,
          ),
        )
        .map((row) =>
          Object.fromEntries(
            Object.entries(row).map(([key, value]) => [
              key,
              value instanceof Uint8Array ? Uint8Array.from(value).buffer : value,
            ]),
          ),
        );
      return { toArray: () => rows as T[] };
    },
  };
  database.exec("CREATE TABLE IF NOT EXISTS test_alarm (time INTEGER NOT NULL)");
  const retained = new Set<Promise<unknown>>();
  const state: DurableObjectPublisherState = {
    waitUntil(operation) {
      retained.add(operation);
      void operation.finally(() => retained.delete(operation));
    },
    storage: {
      sql,
      async sync() {
        // DatabaseSync statements commit before returning.
      },
      async setAlarm(time) {
        database.exec("DELETE FROM test_alarm");
        database
          .prepare("INSERT INTO test_alarm (time) VALUES (?)")
          .run(time instanceof Date ? time.getTime() : time);
      },
      async deleteAlarm() {
        database.exec("DELETE FROM test_alarm");
      },
    },
  };
  return {
    database,
    state,
    alarm: () => database.prepare("SELECT time FROM test_alarm").get()?.time,
    retained,
    close: () => database.close(),
  };
}

export function portableDeferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  void promise.catch(() => {});
  return { promise, resolve, reject };
}
