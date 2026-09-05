package serviceapi

import (
	"net/http"
	"testing"
)

func TestBearerSecretsAuthenticateCurrentAndPrevious(t *testing.T) {
	current := "current-cluster-secret-0123456789"
	previous := "previous-cluster-secret-01234567"
	secrets, err := NewBearerSecrets(current, previous)
	if err != nil {
		t.Fatal(err)
	}
	for name, token := range map[string]string{
		"current":  current,
		"previous": previous,
	} {
		t.Run(name, func(t *testing.T) {
			header := make(http.Header)
			header.Set("Authorization", "Bearer "+token)
			if !secrets.Authenticate(header) {
				t.Fatal("valid service secret was rejected")
			}
		})
	}
	for name, authorization := range map[string]string{
		"missing": "",
		"wrong":   "Bearer wrong-cluster-secret-0123456789",
		"extra":   "Bearer " + current + ",Bearer " + previous,
	} {
		t.Run(name, func(t *testing.T) {
			header := make(http.Header)
			if authorization != "" {
				header.Set("Authorization", authorization)
			}
			if secrets.Authenticate(header) {
				t.Fatal("invalid service secret was accepted")
			}
		})
	}
}

func TestBearerSecretsRejectInvalidConfiguration(t *testing.T) {
	valid := "valid-cluster-secret-012345678901"
	for name, currentPrevious := range map[string][2]string{
		"short":      {"short", ""},
		"whitespace": {valid + " ", ""},
		"duplicate":  {valid, valid},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewBearerSecrets(currentPrevious[0], currentPrevious[1]); err == nil {
				t.Fatal("invalid service secret configuration was accepted")
			}
		})
	}
}
