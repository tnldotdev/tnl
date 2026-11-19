export function invitationChirp() {
  let audio: AudioContext;
  try {
    // create and resume on a click so playback later can use the same context.
    audio = new AudioContext();
  } catch {
    return undefined;
  }
  void audio.resume().catch(() => {});
  return {
    play() {
      if (!document.hidden || audio.state !== "running") return;
      const at = audio.currentTime;
      // two soft, rising modem notes and a short warble.
      const notes = [
        [0, 0.16, 540, 790, "sine"],
        [0.21, 0.18, 910, 1_260, "triangle"],
        [0.43, 0.29, 1_420, 980, "triangle"],
      ] as const;
      for (const [delay, duration, from, to, type] of notes) {
        const start = at + delay;
        const end = start + duration;
        const oscillator = audio.createOscillator();
        const volume = audio.createGain();
        oscillator.type = type;
        oscillator.frequency.setValueAtTime(from, start);
        oscillator.frequency.exponentialRampToValueAtTime(to, end);
        volume.gain.setValueAtTime(0, start);
        volume.gain.linearRampToValueAtTime(0.035, start + 0.025);
        volume.gain.linearRampToValueAtTime(0, end);
        oscillator.connect(volume);
        volume.connect(audio.destination);
        oscillator.onended = () => {
          oscillator.disconnect();
          volume.disconnect();
        };
        oscillator.start(start);
        oscillator.stop(end);
      }
    },
    close() {
      void audio.close().catch(() => {});
    },
  };
}

export function protectHostingTab() {
  let active = true;
  let pending = false;
  let lock: WakeLockSentinel | undefined;
  const warn = (event: BeforeUnloadEvent) => {
    event.preventDefault();
    event.returnValue = true;
  };
  function release() {
    const current = lock;
    lock = undefined;
    if (current !== undefined) void current.release().catch(() => {});
  }
  function visibility() {
    if (document.visibilityState !== "visible") {
      release();
      return;
    }
    if (!active || pending || (lock !== undefined && !lock.released) || !navigator.wakeLock) return;
    pending = true;
    void navigator.wakeLock
      .request("screen")
      .then((acquired) => {
        if (!active || document.visibilityState !== "visible") return acquired.release();
        lock = acquired;
        return undefined;
      })
      .catch(() => {})
      .finally(() => {
        pending = false;
      });
  }
  window.addEventListener("beforeunload", warn);
  document.addEventListener("visibilitychange", visibility);
  visibility();
  return () => {
    active = false;
    window.removeEventListener("beforeunload", warn);
    document.removeEventListener("visibilitychange", visibility);
    release();
  };
}
