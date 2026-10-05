export function AsciiBar({ title, close }: { title?: string; close?: () => void }) {
  return (
    <div class="ascii-bar">
      <span aria-hidden="true">+</span>
      {title && <span class="frame-title">--[ {title} ]</span>}
      <span class="frame-rule" aria-hidden="true">
        {"-".repeat(100)}
      </span>
      {close && (
        <button type="button" class="frame-close" aria-label="Close feedback" onClick={close}>
          [ x ]
        </button>
      )}
      <span aria-hidden="true">+</span>
    </div>
  );
}
