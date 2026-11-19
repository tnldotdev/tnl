package stream

// HandlerOnly selects in-process HTTP handlers on wasm. keep visitor TLS and
// authorization on the shared path, but leave target dialing out of the build.
const HandlerOnly = true
