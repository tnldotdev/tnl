export const MAX_CHUNK_BYTES = 64 * 1024;

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

// go validates the options and owns authorization; this is not another credential model.
export type PrepareOptions = { [key: string]: JsonValue };

// writes are accepted only while the bounded queue has room. keep accepted input
// unchanged until event 2 acknowledges completed bytes, not just acceptance.
export interface ApplicationPump {
  write(bytes: Uint8Array): boolean;
  resume(): void;
}

// 1: data, 2: completed write bytes, 3: EOF, 4: failure.
export type PumpReceiver = (kind: number, value: Uint8Array | number | null) => void;
export type HostPumpReceiver = (kind: number, value: Uint8Array | number | null | Error) => void;

export interface ByteStream {
  // host resume returns the drained 64 kib read window; reads may fill it in chunks.
  startPump?(receive: HostPumpReceiver): ApplicationPump;
  // one read and one write may run concurrently; reads never return an empty chunk.
  read(max: number): Promise<Uint8Array | null>;
  write(bytes: Uint8Array): Promise<void>;
  // close interrupts pending operations and is idempotent.
  close(): Promise<void>;
}

export interface ConnectorHost {
  // raw TCP only: go owns relay transport TLS, multiplexing, and visitor TLS.
  dialTCP(address: string, signal?: AbortSignal): Promise<ByteStream>;
}

export interface ConnectorStream extends ByteStream {
  // application resume grants one owned chunk, after verified TLS setup.
  pump?(receive: PumpReceiver): ApplicationPump | null;
  // for postgres, go sends SSLRequest, requires S, and completes verified TLS.
  // resolving this promise is the boundary after which pg may send credentials.
  startTls(): Promise<void>;
}

export interface ConnectorHandle {
  // actual initial slot zero after preparation; required by real fault qualification.
  readonly selectedRelayAddress?: string;
  open(): Promise<ConnectorStream>;
  close(): Promise<void>;
}

export interface ConnectorBridge {
  diagnostics?(): unknown;
  prepare(
    options: PrepareOptions,
    host: ConnectorHost,
    signal?: AbortSignal,
  ): Promise<ConnectorHandle>;
}
