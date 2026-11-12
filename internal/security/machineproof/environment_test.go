package machineproof

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestEnvironmentVisitorProofBindsEverySelection(t *testing.T) {
	services := map[string]string{"db": "postgres", "api": "http"}
	proof := EnvironmentVisitor("permission", "environment", "prepare", "public", "nonce", services)
	for _, altered := range []string{
		EnvironmentVisitor("other", "environment", "prepare", "public", "nonce", services),
		EnvironmentVisitor("permission", "other", "prepare", "public", "nonce", services),
		EnvironmentVisitor("permission", "environment", "attach", "public", "nonce", services),
		EnvironmentVisitor("permission", "environment", "prepare", "other", "nonce", services),
		EnvironmentVisitor("permission", "environment", "prepare", "public", "other", services),
		EnvironmentVisitor("permission", "environment", "prepare", "public", "nonce", map[string]string{"db": "http", "api": "http"}),
	} {
		if altered == proof {
			t.Fatal("changed authority selection retained its signing scope")
		}
	}
	if proof != EnvironmentVisitor("permission", "environment", "prepare", "public", "nonce", map[string]string{"api": "http", "db": "postgres"}) {
		t.Fatal("map insertion order changed the signing scope")
	}
	assertion := sha256.Sum256([]byte("assertion"))
	possession := EnvironmentVisitorPossession("project", "permission", "environment", "prepare", "public", "nonce", services, assertion)
	if bytes.Equal(possession, EnvironmentVisitorPossession("other", "permission", "environment", "prepare", "public", "nonce", services, assertion)) || bytes.Equal(possession, EnvironmentVisitorPossession("project", "permission", "environment", "prepare", "public", "nonce", services, sha256.Sum256([]byte("other")))) {
		t.Fatal("ephemeral possession proof omitted project or assertion binding")
	}
}
