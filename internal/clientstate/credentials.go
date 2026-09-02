package clientstate

import (
	"errors"
	"os"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
)

type AccessCredential struct {
	Token        credentials.AccessToken
	CredentialID credentials.CredentialID
	ExpiresAt    time.Time
}

type accessCredentialFile struct {
	Version      int       `json:"version"`
	AccessToken  []byte    `json:"access_token"`
	CredentialID string    `json:"credential_id"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func (s *Store) AccessCredential() (AccessCredential, bool, error) {
	var stored accessCredentialFile
	found, err := readJSON(s.credentialsPath, &stored)
	if err != nil || !found {
		return AccessCredential{}, found, err
	}
	plaintext, err := s.secrets.Open("access-credential", stored.AccessToken)
	if err != nil {
		return AccessCredential{}, true, err
	}
	token := credentials.AccessToken(plaintext)
	credentialID, _, err := credentials.ParseAccessToken(token)
	if err != nil || stored.Version != stateVersion || credentialID.String() != stored.CredentialID ||
		stored.ExpiresAt.IsZero() {
		return AccessCredential{}, true, errors.New("clientstate: saved access credential is invalid")
	}
	return AccessCredential{Token: token, CredentialID: credentialID, ExpiresAt: stored.ExpiresAt}, true, nil
}

func (s *Store) SaveAccessCredential(credential AccessCredential) error {
	credentialID, _, err := credentials.ParseAccessToken(credential.Token)
	if err != nil || credentialID != credential.CredentialID || credential.ExpiresAt.IsZero() {
		return errors.New("clientstate: invalid access credential")
	}
	protected, err := s.secrets.Seal("access-credential", []byte(credential.Token))
	if err != nil {
		return err
	}
	return writeJSON(s.credentialsPath, accessCredentialFile{
		Version: stateVersion, AccessToken: protected,
		CredentialID: credential.CredentialID.String(), ExpiresAt: credential.ExpiresAt,
	})
}

func (s *Store) RemoveAccessCredential() error {
	if err := os.Remove(s.credentialsPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(s.serverDir)
}
