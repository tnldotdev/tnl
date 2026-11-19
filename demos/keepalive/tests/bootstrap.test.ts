import { expect, it, vi } from "vitest";
import { CONFIG_PATH } from "../src/hosting/config.ts";
import { HostingUnavailable, hostTab } from "../src/hosting/tab.ts";

it("does not probe peers or download hosting files when bootstrap is unavailable", async () => {
  const fetch = vi
    .fn<typeof globalThis.fetch>()
    .mockResolvedValue(new Response(null, { status: 503 }));
  vi.stubGlobal("fetch", fetch);
  try {
    const { signal } = new AbortController();
    await expect(hostTab(true, signal, signal, vi.fn())).rejects.toBeInstanceOf(HostingUnavailable);
    expect(fetch).toHaveBeenCalledExactlyOnceWith(
      CONFIG_PATH,
      expect.objectContaining({ method: "POST" }),
    );
  } finally {
    vi.unstubAllGlobals();
  }
});
