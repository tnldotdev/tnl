package workloadproof

import (
	"bytes"
	"encoding/hex"
	"math"
	"testing"
)

func TestRenewDigest(t *testing.T) {
	for _, test := range []struct {
		sequence int64
		digest   string
	}{
		{1, "c02156a4b4489f475062d35384fbc0a8626a46a897c67562e460835a4cf4b8b4"},
		{math.MaxInt64, "f4c3c2a6325cbdff1628e61b69d2be4af156dcca2790b69e2784d6b47b94713d"},
	} {
		if actual := hex.EncodeToString(Renew("wls_example", test.sequence)); actual != test.digest {
			t.Fatal("renewal digest changed", actual)
		}
	}
	base := Renew("wls_example", 1)
	for _, other := range [][]byte{Renew("wls_other", 1), Renew("wls_example", 2), Attach("wls_example", [32]byte{}), Exchange("", "", "", "", "", [32]byte{}, nil)} {
		if bytes.Equal(base, other) {
			t.Fatal("renewal proof did not bind its operation, session and sequence")
		}
	}
}
