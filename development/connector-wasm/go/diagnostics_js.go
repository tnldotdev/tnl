//go:build js && wasm

package main

import (
	"crypto/tls"
	"encoding/json"
	"runtime"
	"syscall/js"
)

// counters contain sizes and operation counts only, never byte contents, endpoint
// names or credentials. this executable is single-threaded js/wasm; snapshots run
// synchronously between goroutine resumptions and do not reset live counters.
type bridgeCounters struct {
	ApplicationPumpStarts        uint64 `json:"applicationPumpStarts"`
	ApplicationPumpWrites        uint64 `json:"applicationPumpWrites"`
	ApplicationPumpReads         uint64 `json:"applicationPumpReads"`
	ApplicationPumpNotifications uint64 `json:"applicationPumpNotifications"`
	HostPumpStarts               uint64 `json:"hostPumpStarts"`
	HostPumpNotifications        uint64 `json:"hostPumpNotifications"`
	HostPumpReads                uint64 `json:"hostPumpReads"`
	HostPumpWrites               uint64 `json:"hostPumpWrites"`
	ApplicationReads             uint64 `json:"applicationReads"`
	ApplicationReadBytes         uint64 `json:"applicationReadBytes"`
	ApplicationReadAllocated     uint64 `json:"applicationReadAllocated"`
	ApplicationWrites            uint64 `json:"applicationWrites"`
	ApplicationWriteBytes        uint64 `json:"applicationWriteBytes"`
	ApplicationWriteAllocated    uint64 `json:"applicationWriteAllocated"`
	HostReads                    uint64 `json:"hostReads"`
	HostReadBytes                uint64 `json:"hostReadBytes"`
	HostWrites                   uint64 `json:"hostWrites"`
	HostWriteBytes               uint64 `json:"hostWriteBytes"`
	PromiseWaits                 uint64 `json:"promiseWaits"`
	ApplicationPromises          uint64 `json:"applicationPromises"`
	SharedPromiseWaits           uint64 `json:"sharedPromiseWaits"`
	PromiseExecutors             uint64 `json:"promiseExecutors"`
	// callback registrations count per-operation Go js.FuncOf calls, including
	// promise executors. native JS bound functions do not register Go callbacks.
	CallbackRegistrations uint64 `json:"callbackRegistrations"`
	PersistentCallbacks   uint64 `json:"persistentCallbacks"`
}

var counters bridgeCounters
var negotiated = make(map[string]string)

func observeTLS(role string, state tls.ConnectionState) {
	negotiated[role] = tls.CipherSuiteName(state.CipherSuite)
}

func diagnostics() js.Value {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	value := struct {
		Counters bridgeCounters    `json:"counters"`
		Memory   map[string]uint64 `json:"memory"`
		Ciphers  map[string]string `json:"ciphers"`
	}{counters, map[string]uint64{
		"totalAlloc": memory.TotalAlloc, "mallocs": memory.Mallocs,
		"heapAlloc": memory.HeapAlloc, "heapInuse": memory.HeapInuse,
		"numGC": uint64(memory.NumGC), "pauseTotalNs": memory.PauseTotalNs,
	}, negotiated}
	b, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return js.Global().Get("JSON").Call("parse", string(b))
}
