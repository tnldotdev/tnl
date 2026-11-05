package stream

import "encoding/base64"

func connectorPairSecret(encoded string) ([32]byte, error) {
	var key [32]byte
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	defer clear(decoded)
	if err != nil || len(decoded) != len(key) || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return key, ErrServiceConnection
	}
	copy(key[:], decoded)
	if key == [32]byte{} {
		return key, ErrServiceConnection
	}
	return key, nil
}
