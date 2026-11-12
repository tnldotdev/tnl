package identity

import (
	"encoding/hex"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func validEnvironmentPublication(value *controlv1.EnvironmentPublication) bool {
	if value == nil || !opaqueid.Valid(value.EnvironmentId, opaqueid.EnvironmentPrefix) || value.MutationRevision < 1 || len(value.ConfigurationHash) != 64 {
		return false
	}
	hash, err := hex.DecodeString(value.ConfigurationHash)
	return err == nil && hex.EncodeToString(hash) == value.ConfigurationHash
}

func cloneEnvironmentPublication(value *controlv1.EnvironmentPublication) *controlv1.EnvironmentPublication {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func sameEnvironmentPublication(a, b *controlv1.EnvironmentPublication) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
