package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/acmeclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
)

type acmeAPI interface {
	NewOrder(context.Context, []string, string) (acmeclient.Order, error)
	GetOrder(context.Context, string) (acmeclient.Order, error)
	GetAuthorization(context.Context, string) (acmeclient.Authorization, error)
	AcceptChallenge(context.Context, string) (time.Time, error)
	FinalizeOrder(context.Context, string, string, []byte) (acmeclient.Order, error)
	DownloadCertificate(context.Context, string) ([]byte, error)
	KeyAuthorization(string) (string, error)
}

type acmeClientFactory func(controlstate.ACMEAccount) (acmeAPI, error)

func newACMEClientFactory(httpClient *http.Client) acmeClientFactory {
	return func(account controlstate.ACMEAccount) (acmeAPI, error) {
		return newACMEClient(httpClient, account)
	}
}

func newACMEClient(httpClient *http.Client, account controlstate.ACMEAccount) (*acmeclient.Client, error) {
	key, err := parseACMEAccountKey(account.AccountKeyDER)
	if err != nil {
		return nil, err
	}
	return acmeclient.New(httpClient, account.DirectoryURL, key, account.AccountURL)
}

func parseACMEAccountKey(keyDER []byte) (*ecdsa.PrivateKey, error) {
	value, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, fmt.Errorf("certificates: parse ACME account key: %w", err)
	}
	key, ok := value.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("certificates: ACME account key is not ECDSA")
	}
	return key, nil
}

// ACMEAccountStore persists ACME account registration separately from certificate work.
type ACMEAccountStore interface {
	UpdateACMEAccountRegistration(context.Context, string, string, string, string, time.Time) (controlstate.ACMEAccount, error)
}

// ReconcileACMEAccount registers or refreshes an ACME account and persists the result.
func ReconcileACMEAccount(
	ctx context.Context,
	store ACMEAccountStore,
	httpClient *http.Client,
	account controlstate.ACMEAccount,
	acceptTerms bool,
	now time.Time,
) (controlstate.ACMEAccount, error) {
	client, err := newACMEClient(httpClient, account)
	if err != nil {
		return controlstate.ACMEAccount{}, err
	}
	registered, directory, err := client.ReconcileAccount(ctx, account.ContactEmail, acceptTerms)
	if err != nil {
		return controlstate.ACMEAccount{}, fmt.Errorf("certificates: reconcile ACME account: %w", err)
	}
	if registered.Status != "valid" {
		return controlstate.ACMEAccount{}, fmt.Errorf("certificates: ACME account status is %q", registered.Status)
	}
	acceptedTerms := account.AcceptedTerms
	if acceptTerms {
		acceptedTerms = directory.Meta.TermsOfService
	}
	updated, err := store.UpdateACMEAccountRegistration(
		ctx, account.ID, account.ContactEmail, registered.URL, acceptedTerms, now,
	)
	if err != nil {
		return controlstate.ACMEAccount{}, fmt.Errorf("certificates: persist ACME account registration: %w", err)
	}
	return updated, nil
}
