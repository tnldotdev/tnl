package state

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/zalando/go-keyring"
)

var memoryKeychain atomic.Pointer[testKeychain]
var memoryKeychainOnce sync.Once

// UseMemoryKeychainForTesting replaces only default Keychain access for this test
// process. call before starting workers. explicit Keychain selection stays real.
// the macOS store is concurrency-safe and never reset beneath another fixture.
func UseMemoryKeychainForTesting() {
	if !testing.Testing() {
		panic("memory Keychain requires a Go test process")
	}
	memoryKeychainOnce.Do(func() {
		memoryKeychain.Store(&testKeychain{values: make(map[string]string)})
	})
}

type testKeychain struct {
	mu     sync.Mutex
	values map[string]string
}

func (m *testKeychain) get(service, account string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if value, ok := m.values[service+"\x00"+account]; ok {
		return value, nil
	}
	return "", keyring.ErrNotFound
}

func (m *testKeychain) set(service, account, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[service+"\x00"+account] = value
	return nil
}
