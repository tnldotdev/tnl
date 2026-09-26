package credentials

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestCredentialDerivation(t *testing.T) {
	// Independently calculated HMAC-SHA256 vectors: key bytes 00..1f,
	// context "fixture/context", and each documented v1 domain plus NUL.
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index)
	}
	const context = "fixture/context"
	var secrets []string
	for _, test := range []struct {
		name, token, hash string
		derive            func([]byte, string) (string, SecretHash, error)
		parse             func(string) (SecretHash, error)
		invalid           error
	}{
		{
			name:  "publish run",
			token: "tnl_session_uaClN6xl_O2qMKEpmKit_g.rB9NORvCrc7DyCVRBTTaj50IG0WazY5BYcJLtMidxgg",
			hash:  "2ce1947b098f8692bc0cbcd5e989d781a62e359976ec3baab9a47c1373f96b04",
			derive: func(key []byte, context string) (string, SecretHash, error) {
				token, _, hash, err := DerivePublishRunToken(key, context)
				return token.String(), hash, err
			},
			parse: func(token string) (SecretHash, error) {
				_, hash, err := ParsePublishRunToken(PublishRunToken(token))
				return hash, err
			},
			invalid: ErrInvalidPublishRunToken,
		},
		{
			name:  "invitation",
			token: "tnl_invitation_zbIiIFpdzCzD37fiGViJfA.D1v8T1Yyriei_c7xIBIbnPFGd7uOj7PM1Wt-p-DKC2M",
			hash:  "575636ae9fafea41b3c2c0fcb9c8cea584af22444bb748899a178139bef9dc3d",
			derive: func(key []byte, context string) (string, SecretHash, error) {
				token, hash, err := DeriveInvitationToken(key, context)
				return token.String(), hash, err
			},
			parse:   func(token string) (SecretHash, error) { return ParseInvitationToken(InvitationToken(token)) },
			invalid: ErrInvalidInvitationToken,
		},
		{
			name:  "publisher connection",
			token: "tnl_connection_6AKcUBa6UAEygj39eQnfmw.iMFSeiBcJTC0Khu3Kou81BCT9LYvxFRr9OlKYEZYrM8",
			hash:  "0b4f0f9b31208ee3489dafe837b271657e1f784fa9aad3b1081888d7966648c5",
			derive: func(key []byte, context string) (string, SecretHash, error) {
				session := PublishRunToken("tnl_session_AAECAwQFBgcICQoLDA0ODw." + base64.RawURLEncoding.EncodeToString(key))
				token, hash, err := DerivePublisherConnectionCredential(session, context)
				return token.String(), hash, err
			},
			parse: func(token string) (SecretHash, error) {
				return ParsePublisherConnectionCredential(PublisherConnectionCredential(token))
			},
			invalid: ErrInvalidPublishRunToken,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var baselineToken string
			for range 2 {
				token, hash, err := test.derive(key, context)
				if err != nil || token != test.token || hex.EncodeToString(hash[:]) != test.hash {
					t.Fatalf("derived = %q, %x, %v; want %q, %s", token, hash, err, test.token, test.hash)
				}
				parsed, err := test.parse(token)
				if err != nil || parsed != hash {
					t.Fatalf("parse = %x, %v", parsed, err)
				}
				baselineToken = token
			}
			changedKey := bytes.Clone(key)
			changedKey[0] ^= 1
			for _, input := range []struct {
				key     []byte
				context string
			}{{changedKey, context}, {key, context + "/other"}} {
				token, hash, err := test.derive(input.key, input.context)
				_, secret, _ := strings.Cut(token, ".")
				_, baselineSecret, _ := strings.Cut(test.token, ".")
				if err != nil || secret == baselineSecret || hex.EncodeToString(hash[:]) == test.hash {
					t.Fatalf("changed input did not change secret and digest: %q, %x, %v", token, hash, err)
				}
			}
			for _, input := range []struct {
				key     []byte
				context string
			}{{key[:31], context}, {nil, context}, {key, ""}} {
				if token, hash, err := test.derive(input.key, input.context); !errors.Is(err, test.invalid) || token != "" || hash != (SecretHash{}) {
					t.Fatalf("invalid derivation = %q, %x, %v", token, hash, err)
				}
			}
			_, secret, _ := strings.Cut(baselineToken, ".")
			for _, previous := range secrets {
				if secret == previous {
					t.Fatal("credential domains share secret material")
				}
			}
			secrets = append(secrets, secret)
		})
	}
	_, id, _, err := DerivePublishRunToken(key, context)
	if err != nil || id != "uaClN6xl_O2qMKEpmKit_g" {
		t.Fatalf("lookup ID = %q, %v", id, err)
	}
	if _, _, err := DerivePublisherConnectionCredential("tnl_login_AAECAwQFBgcICQoLDA0ODw.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", context); !errors.Is(err, ErrInvalidPublishRunToken) {
		t.Fatalf("wrong credential class = %v", err)
	}
}
