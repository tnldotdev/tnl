package certificates

import (
	"context"
	"crypto"
	"net/http"

	legoacme "github.com/go-acme/lego/v5/acme"
	legoapi "github.com/go-acme/lego/v5/acme/api"
)

type acmeClient interface {
	Directory() legoacme.Directory
	KeyAuthorization(string) (string, error)
	CreateAccount(context.Context, legoacme.Account) (legoacme.ExtendedAccount, error)
	GetAccount(context.Context, string) (legoacme.Account, error)
	UpdateAccount(context.Context, string, legoacme.Account) (legoacme.Account, error)
	CreateOrder(context.Context, []string, *legoapi.OrderOptions) (legoacme.ExtendedOrder, error)
	GetOrder(context.Context, string) (legoacme.ExtendedOrder, error)
	GetAuthorization(context.Context, string) (legoacme.Authorization, error)
	AcceptChallenge(context.Context, string) (legoacme.ExtendedChallenge, error)
	FinalizeOrder(context.Context, string, []byte) (legoacme.ExtendedOrder, error)
	GetCertificate(context.Context, string) (*legoacme.RawCertificate, error)
}

type legoClient struct{ core *legoapi.Core }

func newLegoClient(httpClient *http.Client, directoryURL, kid string, key crypto.Signer) (acmeClient, error) {
	core, err := legoapi.New(httpClient, "tnld/1", directoryURL, kid, key)
	if err != nil {
		return nil, err
	}
	return &legoClient{core: core}, nil
}

func (c *legoClient) Directory() legoacme.Directory { return c.core.GetDirectory() }

func (c *legoClient) KeyAuthorization(token string) (string, error) {
	return c.core.GetKeyAuthorization(token)
}

func (c *legoClient) CreateAccount(ctx context.Context, request legoacme.Account) (legoacme.ExtendedAccount, error) {
	return c.core.Accounts.New(ctx, request)
}

func (c *legoClient) GetAccount(ctx context.Context, accountURL string) (legoacme.Account, error) {
	return c.core.Accounts.Get(ctx, accountURL)
}

func (c *legoClient) UpdateAccount(
	ctx context.Context,
	accountURL string,
	request legoacme.Account,
) (legoacme.Account, error) {
	return c.core.Accounts.Update(ctx, accountURL, request)
}

func (c *legoClient) CreateOrder(
	ctx context.Context,
	domains []string,
	options *legoapi.OrderOptions,
) (legoacme.ExtendedOrder, error) {
	return c.core.Orders.New(ctx, domains, options)
}

func (c *legoClient) GetOrder(ctx context.Context, orderURL string) (legoacme.ExtendedOrder, error) {
	return c.core.Orders.Get(ctx, orderURL)
}

func (c *legoClient) GetAuthorization(ctx context.Context, authorizationURL string) (legoacme.Authorization, error) {
	return c.core.Authorizations.Get(ctx, authorizationURL)
}

func (c *legoClient) AcceptChallenge(ctx context.Context, challengeURL string) (legoacme.ExtendedChallenge, error) {
	return c.core.Challenges.New(ctx, challengeURL)
}

func (c *legoClient) FinalizeOrder(ctx context.Context, finalizeURL string, csrDER []byte) (legoacme.ExtendedOrder, error) {
	return c.core.Orders.UpdateForCSR(ctx, finalizeURL, csrDER)
}

func (c *legoClient) GetCertificate(ctx context.Context, certificateURL string) (*legoacme.RawCertificate, error) {
	return c.core.Certificates.Get(ctx, certificateURL, true)
}
