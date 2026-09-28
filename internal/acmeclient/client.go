package acmeclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxResponseSize = 2 << 20

type Directory struct {
	NewNonce   string            `json:"newNonce"`
	NewAccount string            `json:"newAccount"`
	NewOrder   string            `json:"newOrder"`
	Meta       DirectoryMetadata `json:"meta"`
}

type DirectoryMetadata struct {
	TermsOfService string                     `json:"termsOfService"`
	Profiles       map[string]json.RawMessage `json:"profiles"`
}

type Account struct {
	URL     string
	Status  string
	Contact []string
}

type Order struct {
	URL            string
	RetryAfter     time.Time    `json:"-"`
	Status         string       `json:"status"`
	Expires        *time.Time   `json:"expires"`
	Identifiers    []Identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Authorization struct {
	URL        string
	RetryAfter time.Time   `json:"-"`
	Status     string      `json:"status"`
	Identifier Identifier  `json:"identifier"`
	Wildcard   bool        `json:"wildcard"`
	Expires    *time.Time  `json:"expires"`
	Challenges []Challenge `json:"challenges"`
}

type Challenge struct {
	Type      string     `json:"type"`
	URL       string     `json:"url"`
	Status    string     `json:"status"`
	Token     string     `json:"token"`
	Validated *time.Time `json:"validated"`
	Error     *Problem   `json:"error"`
}

type Problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

type Error struct {
	Status     int
	Type       string
	Detail     string
	RetryAfter time.Time
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("ACME request failed (%d, %s): %s", e.Status, e.Type, e.Detail)
	}
	return fmt.Sprintf("ACME request failed (%d, %s)", e.Status, e.Type)
}

func (e *Error) Terminal() bool {
	// An ACME resource that no longer exists cannot become valid on retry.
	// In particular, Let's Encrypt returns 404 for expired authorizations.
	if e.Status == http.StatusNotFound || e.Status == http.StatusGone {
		return true
	}
	switch pathBase(e.Type) {
	case "badCSR", "rejectedIdentifier", "unauthorized", "unsupportedIdentifier", "userActionRequired":
		return true
	default:
		return false
	}
}

type Client struct {
	httpClient   *http.Client
	directoryURL string
	key          *ecdsa.PrivateKey

	mu         sync.Mutex
	directory  Directory
	nonce      string
	accountURL string
}

func New(httpClient *http.Client, directoryURL string, key *ecdsa.PrivateKey, accountURL string) (*Client, error) {
	if httpClient == nil || key == nil || key.Curve != elliptic.P256() ||
		!validURL(directoryURL) || accountURL != "" && !validURL(accountURL) {
		return nil, errors.New("acmeclient: invalid client configuration")
	}
	return &Client{httpClient: httpClient, directoryURL: directoryURL, key: key, accountURL: accountURL}, nil
}

func (c *Client) Discover(ctx context.Context) (Directory, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.directory.NewNonce != "" {
		return c.directory, nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.directoryURL, nil)
	if err != nil {
		return Directory{}, fmt.Errorf("acmeclient: create directory request: %w", err)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return Directory{}, fmt.Errorf("acmeclient: fetch directory: %w", err)
	}
	body, readErr := readResponse(response)
	if readErr != nil {
		return Directory{}, readErr
	}
	if response.StatusCode != http.StatusOK {
		return Directory{}, responseError(response, body)
	}
	var directory Directory
	if err := json.Unmarshal(body, &directory); err != nil || !validURL(directory.NewNonce) ||
		!validURL(directory.NewAccount) || !validURL(directory.NewOrder) ||
		directory.Meta.TermsOfService != "" && !validURI(directory.Meta.TermsOfService) {
		return Directory{}, errors.New("acmeclient: directory response is invalid")
	}
	c.directory = directory
	return directory, nil
}

func (c *Client) ReconcileAccount(ctx context.Context, email string, acceptTerms bool) (Account, Directory, error) {
	if strings.TrimSpace(email) != email || email == "" || strings.ContainsAny(email, "\r\n") {
		return Account{}, Directory{}, errors.New("acmeclient: invalid account email")
	}
	directory, err := c.Discover(ctx)
	if err != nil {
		return Account{}, Directory{}, err
	}
	contact := "mailto:" + email
	if c.accountURL == "" {
		payload := struct {
			Contact              []string `json:"contact"`
			TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
		}{Contact: []string{contact}, TermsOfServiceAgreed: acceptTerms}
		body, header, err := c.post(ctx, directory.NewAccount, payload, false)
		if err != nil {
			return Account{}, Directory{}, err
		}
		c.accountURL = header.Get("Location")
		if !validURL(c.accountURL) {
			return Account{}, Directory{}, errors.New("acmeclient: account response is missing its URL")
		}
		account, err := decodeAccount(body, c.accountURL)
		return account, directory, err
	}
	body, _, err := c.postAsGet(ctx, c.accountURL)
	if err != nil {
		var acmeError *Error
		if !errors.As(err, &acmeError) || pathBase(acmeError.Type) != "accountDoesNotExist" {
			return Account{}, Directory{}, err
		}
		c.accountURL = ""
		return c.ReconcileAccount(ctx, email, acceptTerms)
	}
	account, err := decodeAccount(body, c.accountURL)
	if err != nil {
		return Account{}, Directory{}, err
	}
	if account.Status != "valid" {
		return Account{}, Directory{}, fmt.Errorf("acmeclient: account status is %q", account.Status)
	}
	if !slices.Equal(account.Contact, []string{contact}) {
		body, _, err = c.post(ctx, c.accountURL, struct {
			Contact []string `json:"contact"`
		}{Contact: []string{contact}}, true)
		if err != nil {
			return Account{}, Directory{}, err
		}
		account, err = decodeAccount(body, c.accountURL)
	}
	return account, directory, err
}

func (c *Client) NewOrder(ctx context.Context, identifiers []string, profile string) (Order, error) {
	directory, err := c.Discover(ctx)
	if err != nil {
		return Order{}, err
	}
	payload := struct {
		Identifiers []Identifier `json:"identifiers"`
		Profile     string       `json:"profile,omitempty"`
	}{Profile: profile, Identifiers: make([]Identifier, len(identifiers))}
	for index, identifier := range identifiers {
		payload.Identifiers[index] = Identifier{Type: "dns", Value: identifier}
	}
	body, header, err := c.post(ctx, directory.NewOrder, payload, true)
	if err != nil {
		return Order{}, err
	}
	order, err := decodeOrder(body, header.Get("Location"))
	order.RetryAfter = parseRetryAfter(header.Get("Retry-After"), time.Now())
	return order, err
}

func (c *Client) GetOrder(ctx context.Context, orderURL string) (Order, error) {
	body, header, err := c.postAsGet(ctx, orderURL)
	if err != nil {
		return Order{}, err
	}
	order, err := decodeOrder(body, orderURL)
	order.RetryAfter = parseRetryAfter(header.Get("Retry-After"), time.Now())
	return order, err
}

func (c *Client) GetAuthorization(ctx context.Context, authorizationURL string) (Authorization, error) {
	body, header, err := c.postAsGet(ctx, authorizationURL)
	if err != nil {
		return Authorization{}, err
	}
	var authorization Authorization
	if err := json.Unmarshal(body, &authorization); err != nil || authorization.Status == "" ||
		authorization.Identifier.Type != "dns" || authorization.Identifier.Value == "" {
		return Authorization{}, errors.New("acmeclient: authorization response is invalid")
	}
	authorization.URL = authorizationURL
	authorization.RetryAfter = parseRetryAfter(header.Get("Retry-After"), time.Now())
	return authorization, nil
}

func (c *Client) AcceptChallenge(ctx context.Context, challengeURL string) (time.Time, error) {
	_, header, err := c.post(ctx, challengeURL, struct{}{}, true)
	if err != nil {
		return time.Time{}, err
	}
	return parseRetryAfter(header.Get("Retry-After"), time.Now()), nil
}

func (c *Client) FinalizeOrder(ctx context.Context, orderURL, finalizeURL string, csrDER []byte) (Order, error) {
	body, header, err := c.post(ctx, finalizeURL, struct {
		CSR string `json:"csr"`
	}{CSR: base64.RawURLEncoding.EncodeToString(csrDER)}, true)
	if err != nil {
		return Order{}, err
	}
	responseOrderURL := header.Get("Location")
	if responseOrderURL == "" {
		responseOrderURL = orderURL
	}
	order, err := decodeOrder(body, responseOrderURL)
	order.RetryAfter = parseRetryAfter(header.Get("Retry-After"), time.Now())
	return order, err
}

func (c *Client) DownloadCertificate(ctx context.Context, certificateURL string) ([]byte, error) {
	body, _, err := c.postAsGet(ctx, certificateURL)
	return body, err
}

func (c *Client) KeyAuthorization(token string) (string, error) {
	if token == "" {
		return "", errors.New("acmeclient: challenge token is empty")
	}
	thumbprint, err := c.thumbprint()
	if err != nil {
		return "", err
	}
	return token + "." + thumbprint, nil
}

func (c *Client) postAsGet(ctx context.Context, endpoint string) ([]byte, http.Header, error) {
	return c.postEncoded(ctx, endpoint, nil, true)
}

func (c *Client) post(ctx context.Context, endpoint string, value any, useAccount bool) ([]byte, http.Header, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, nil, fmt.Errorf("acmeclient: encode request: %w", err)
	}
	return c.postEncoded(ctx, endpoint, payload, useAccount)
}

func (c *Client) postEncoded(ctx context.Context, endpoint string, payload []byte, useAccount bool) ([]byte, http.Header, error) {
	if !validURL(endpoint) {
		return nil, nil, errors.New("acmeclient: invalid request URL")
	}
	for attempt := 0; attempt < 2; attempt++ {
		nonce, err := c.takeNonce(ctx)
		if err != nil {
			return nil, nil, err
		}
		requestBody, err := c.sign(endpoint, nonce, payload, useAccount)
		if err != nil {
			return nil, nil, err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(requestBody))
		if err != nil {
			return nil, nil, fmt.Errorf("acmeclient: create request: %w", err)
		}
		request.Header.Set("Content-Type", "application/jose+json")
		response, err := c.httpClient.Do(request)
		if err != nil {
			return nil, nil, fmt.Errorf("acmeclient: send request: %w", err)
		}
		c.storeNonce(response.Header.Get("Replay-Nonce"))
		body, readErr := readResponse(response)
		if readErr != nil {
			return nil, nil, readErr
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			return body, response.Header.Clone(), nil
		}
		requestError := responseError(response, body)
		var acmeError *Error
		if attempt == 0 && errors.As(requestError, &acmeError) && pathBase(acmeError.Type) == "badNonce" {
			continue
		}
		return nil, nil, requestError
	}
	return nil, nil, errors.New("acmeclient: bad nonce retry exhausted")
}

func (c *Client) takeNonce(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.nonce != "" {
		nonce := c.nonce
		c.nonce = ""
		c.mu.Unlock()
		return nonce, nil
	}
	directory := c.directory
	c.mu.Unlock()
	if directory.NewNonce == "" {
		var err error
		directory, err = c.Discover(ctx)
		if err != nil {
			return "", err
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, directory.NewNonce, nil)
	if err != nil {
		return "", fmt.Errorf("acmeclient: create nonce request: %w", err)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("acmeclient: fetch nonce: %w", err)
	}
	_, readErr := readResponse(response)
	if readErr != nil {
		return "", readErr
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", &Error{Status: response.StatusCode, Type: "nonce", Detail: response.Status}
	}
	nonce := response.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", errors.New("acmeclient: nonce response is missing Replay-Nonce")
	}
	return nonce, nil
}

func (c *Client) storeNonce(nonce string) {
	if nonce == "" {
		return
	}
	c.mu.Lock()
	c.nonce = nonce
	c.mu.Unlock()
}

func (c *Client) sign(endpoint, nonce string, payload []byte, useAccount bool) ([]byte, error) {
	protected := map[string]any{"alg": "ES256", "nonce": nonce, "url": endpoint}
	if useAccount {
		if c.accountURL == "" {
			return nil, errors.New("acmeclient: account URL is not configured")
		}
		protected["kid"] = c.accountURL
	} else {
		protected["jwk"] = c.jwk()
	}
	protectedJSON, err := json.Marshal(protected)
	if err != nil {
		return nil, fmt.Errorf("acmeclient: encode protected header: %w", err)
	}
	protected64 := base64.RawURLEncoding.EncodeToString(protectedJSON)
	payload64 := base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(protected64 + "." + payload64))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("acmeclient: sign request: %w", err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return json.Marshal(struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}{Protected: protected64, Payload: payload64, Signature: base64.RawURLEncoding.EncodeToString(signature)})
}

func (c *Client) thumbprint() (string, error) {
	value, err := json.Marshal(c.jwk())
	if err != nil {
		return "", fmt.Errorf("acmeclient: encode account key: %w", err)
	}
	digest := sha256.Sum256(value)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func (c *Client) jwk() struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
} {
	return struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{
		Crv: "P-256", Kty: "EC",
		X: base64.RawURLEncoding.EncodeToString(paddedCoordinate(c.key.X)),
		Y: base64.RawURLEncoding.EncodeToString(paddedCoordinate(c.key.Y)),
	}
}

func decodeAccount(body []byte, accountURL string) (Account, error) {
	var wire struct {
		Status  string   `json:"status"`
		Contact []string `json:"contact"`
	}
	if err := json.Unmarshal(body, &wire); err != nil || wire.Status == "" {
		return Account{}, errors.New("acmeclient: account response is invalid")
	}
	return Account{URL: accountURL, Status: wire.Status, Contact: slices.Clone(wire.Contact)}, nil
}

func decodeOrder(body []byte, orderURL string) (Order, error) {
	var order Order
	if err := json.Unmarshal(body, &order); err != nil || !validURL(orderURL) || order.Status == "" ||
		order.Finalize != "" && !validURL(order.Finalize) {
		return Order{}, errors.New("acmeclient: order response is invalid")
	}
	for _, authorizationURL := range order.Authorizations {
		if !validURL(authorizationURL) {
			return Order{}, errors.New("acmeclient: order authorization URL is invalid")
		}
	}
	if order.Certificate != "" && !validURL(order.Certificate) {
		return Order{}, errors.New("acmeclient: order certificate URL is invalid")
	}
	order.URL = orderURL
	return order, nil
}

func readResponse(response *http.Response) ([]byte, error) {
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("acmeclient: read response: %w", err)
	}
	if len(body) > maxResponseSize {
		return nil, errors.New("acmeclient: response exceeds size limit")
	}
	return body, nil
}

func responseError(response *http.Response, body []byte) error {
	var problem struct {
		Type   string `json:"type"`
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal(body, &problem)
	if problem.Type == "" {
		problem.Type = "urn:ietf:params:acme:error:serverInternal"
	}
	if problem.Detail == "" {
		problem.Detail = response.Status
	}
	return &Error{
		Status: response.StatusCode, Type: problem.Type, Detail: problem.Detail,
		RetryAfter: parseRetryAfter(response.Header.Get("Retry-After"), time.Now()),
	}
}

func parseRetryAfter(value string, now time.Time) time.Time {
	if seconds, err := strconv.ParseInt(value, 10, 32); err == nil && seconds >= 0 {
		return now.Add(time.Duration(seconds) * time.Second)
	}
	if result, err := http.ParseTime(value); err == nil {
		return result
	}
	return time.Time{}
}

func paddedCoordinate(value *big.Int) []byte {
	result := make([]byte, 32)
	value.FillBytes(result)
	return result
}

func validURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") && parsed.Host != "" && parsed.User == nil
}

func validURI(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.IsAbs() && parsed.User == nil
}

func pathBase(value string) string {
	if index := strings.LastIndexByte(value, ':'); index >= 0 {
		return value[index+1:]
	}
	return value
}
