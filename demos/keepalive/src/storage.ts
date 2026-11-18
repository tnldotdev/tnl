import * as z from "zod";
import { startTime } from "./peers.ts";
import { type Asset, type Release, verifyAsset } from "./release.ts";

const storeName = "releases";
const storedFiles = z.map(z.string(), z.instanceof(ArrayBuffer));

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("keepalive-site", 1);
    request.onupgradeneeded = () => request.result.createObjectStore(storeName);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function read(key: string): Promise<unknown> {
  const db = await openDB();
  try {
    return await new Promise((resolve, reject) => {
      const request = db.transaction(storeName).objectStore(storeName).get(key);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  } finally {
    db.close();
  }
}

async function write(edit: (store: IDBObjectStore) => void) {
  const db = await openDB();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(storeName, "readwrite");
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(tx.error);
      edit(tx.objectStore(storeName));
    });
  } finally {
    db.close();
  }
}

// one write saves the whole checked copy.
export function saveRelease(release: Release, files: Map<string, ArrayBuffer>) {
  return write((store) => store.put(files, release.id));
}

export async function openRelease(release: Release) {
  const files = storedFiles.parse(await read(release.id));
  for (const asset of release.assets) {
    const bytes = files.get(asset.path);
    if (bytes === undefined) throw new Error("The copy is incomplete.");
    await verifyAsset(asset, new Uint8Array(bytes));
  }
  return (asset: Asset) => {
    const bytes = files.get(asset.path);
    return bytes === undefined ? undefined : new Uint8Array(bytes);
  };
}

export async function rememberStart(releaseID: string, observed: number) {
  const key = `started:${releaseID}`;
  let earliest = observed;
  await write((store) => {
    const request = store.get(key);
    request.onsuccess = () => {
      const saved = startTime(request.result, Date.now());
      earliest = Math.min(saved ?? observed, observed);
      if (earliest !== saved) store.put(earliest, key);
    };
  });
  return earliest;
}
