// Package controlclient calls the tnl control API.
//
// responses normally cannot exceed 1 MiB. a successful response other than HTTP 204
// must contain one non-null JSON value that matches the generated schema. most
// requests time out after 20 seconds; certificate requests time out after 150
// seconds. requests do not follow redirects. network and read failures wrap
// ErrUnavailable, but caller cancellation, invalid responses, and oversized
// responses do not. known server problem codes take precedence over status.
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/httpclient"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const (
	maxResponseBytes       = 1 << 20
	defaultRequestTimeout  = 20 * time.Second
	certificateCallTimeout = 150 * time.Second
)

var (
	ErrUnauthenticated      = failure.Wrap("authenticate control request", failure.Authentication, errors.New("controlclient: unauthenticated"))
	ErrNotFound             = failure.Wrap("read control resource", failure.ServerResourceNotFound, errors.New("controlclient: not found"))
	ErrNameUnavailable      = failure.Wrap("select service hostname", failure.ServerConflict, errors.New("controlclient: service hostname unavailable"))
	ErrStatusConflict       = failure.Wrap("update control state", failure.ServerConflict, errors.New("controlclient: status conflict"))
	ErrProjectManaged       = failure.Wrap("change project-managed resource", failure.ServerConflict, fmt.Errorf("resource is managed by project configuration: %w", ErrStatusConflict))
	ErrCertificateStatus    = failure.Wrap("issue service certificate", failure.CertificateUnavailable, errors.New("controlclient: certificate status conflict"))
	ErrDNSProofPending      = failure.Wrap("configure domain DNS", failure.DNSPending, errors.New("controlclient: DNS setup pending"))
	ErrRateLimited          = failure.Wrap("request control API", failure.ServerRateLimited, errors.New("controlclient: rate limited"))
	ErrUnavailable          = failure.Wrap("request control API", failure.ServerUnavailable, errors.New("controlclient: temporarily unavailable"))
	ErrUnsupported          = failure.Wrap("request control API", failure.ServerResponseInvalid, errors.New("controlclient: unsupported"))
	ErrGuestTrialExhausted  = failure.Wrap("publish guest demo", failure.GuestTrialExhausted, errors.New("controlclient: guest demo trial exhausted"))
	ErrGuestDemoOnly        = failure.Wrap("publish guest demo", failure.GuestDemoOnly, errors.New("controlclient: guest demo only"))
	ErrGuestIPChanged       = failure.Wrap("publish guest demo", failure.GuestIPChanged, errors.New("controlclient: guest demo source IP changed"))
	ErrGuestIssuanceLimited = failure.Wrap("create guest demo", failure.GuestIssuanceLimited, errors.New("controlclient: guest demo issuance limited"))
	ErrMemberHostnameDepth  = failure.Wrap("select service hostname", failure.MemberHostnameDepthExceeded, errors.New("managed-domain member hostname depth exceeded"))
)

type Client struct {
	publisherWaits         publisherWaits
	api                    *controlv1.Client
	access                 credentials.AccessToken
	externalAuthentication bool
	timeout                time.Duration
}

// NewExternallyAuthenticated creates a client whose HTTP transport adds authorization.
func NewExternallyAuthenticated(server string, httpClient *http.Client) (*Client, error) {
	client, err := New(server, httpClient, "")
	if err != nil {
		return nil, err
	}
	client.externalAuthentication = true
	return client, nil
}

func New(server string, httpClient *http.Client, access credentials.AccessToken) (*Client, error) {
	server, err := naming.CanonicalControlURL(server)
	if err != nil {
		return nil, failure.Wrap("select control server", failure.InvalidControlURL, err)
	}
	httpClient = observability.OwnedHTTPClient(httpclient.NoRedirects(httpClient), "control")
	apiClient, err := controlv1.NewClient(
		server,
		controlv1.WithHTTPClient(httpClient),
		controlv1.WithRequestEditorFn(func(_ context.Context, request *http.Request) error {
			request.Header.Set("Accept", "application/json, application/problem+json")
			return nil
		}),
	)
	if err != nil {
		return nil, failure.Wrap("configure control client", failure.ServerRequestInvalid, err)
	}
	return &Client{api: apiClient, access: access, timeout: defaultRequestTimeout}, nil
}

func (c *Client) Discovery(ctx context.Context) (controlv1.ControlDiscovery, error) {
	return request[controlv1.ControlDiscovery](ctx, c, "", c.api.GetControlDiscovery)
}

func (c *Client) ClientIP(ctx context.Context) (controlv1.ClientIPResponse, error) {
	return request[controlv1.ClientIPResponse](ctx, c, "", c.api.GetClientIP)
}

func (c *Client) CreateGuestDemo(ctx context.Context) (controlv1.GuestDemoSession, error) {
	return request[controlv1.GuestDemoSession](ctx, c, "", c.api.CreateGuestDemo)
}

func (c *Client) CreatePreview(ctx context.Context, teamID, key string) (controlv1.Preview, error) {
	params := &controlv1.CreatePreviewParams{IdempotencyKey: key}
	return requestWithAccess[controlv1.Preview](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreatePreview(ctx, params, controlv1.CreatePreviewRequest{TeamId: teamID}, editors...)
	})
}

func (c *Client) GetPreview(ctx context.Context, id string) (controlv1.Preview, error) {
	return requestWithAccess[controlv1.Preview](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetPreview(ctx, id, editors...)
	})
}

func (c *Client) SetPreviewTeamAccess(ctx context.Context, id string, enabled bool) (controlv1.Preview, error) {
	return requestWithAccess[controlv1.Preview](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.SetPreviewTeamAccess(ctx, id, controlv1.SetPreviewTeamAccessRequest{Enabled: enabled}, editors...)
	})
}

func (c *Client) AddPreviewService(ctx context.Context, id, serviceID string) (controlv1.Preview, error) {
	return requestWithAccess[controlv1.Preview](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AddPreviewService(ctx, id, controlv1.AddPreviewServiceRequest{ServiceId: serviceID}, editors...)
	})
}

func (c *Client) CreateShare(ctx context.Context, previewID, key string, body controlv1.CreateShareRequest) (controlv1.ShareCreation, error) {
	params := &controlv1.CreateShareParams{IdempotencyKey: key}
	return requestWithAccess[controlv1.ShareCreation](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateShare(ctx, previewID, params, body, editors...)
	})
}

func (c *Client) CreateServiceShare(ctx context.Context, key string, body controlv1.CreateShareRequest) (controlv1.ShareCreation, error) {
	return requestWithAccess[controlv1.ShareCreation](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateServiceShare(ctx, &controlv1.CreateServiceShareParams{IdempotencyKey: key}, body, editors...)
	})
}

func (c *Client) GetShare(ctx context.Context, id string) (controlv1.Share, error) {
	return requestWithAccess[controlv1.Share](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetShare(ctx, id, editors...)
	})
}

func (c *Client) ListShares(ctx context.Context, previewID string) ([]controlv1.Share, error) {
	return c.listShares(ctx, func(requestCtx context.Context, cursor *string, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListShares(requestCtx, previewID, &controlv1.ListSharesParams{Cursor: cursor}, editors...)
	})
}

func (c *Client) ListTeamShares(ctx context.Context, teamID string) ([]controlv1.Share, error) {
	return c.listShares(ctx, func(requestCtx context.Context, cursor *string, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListTeamShares(requestCtx, &controlv1.ListTeamSharesParams{TeamId: teamID, Cursor: cursor}, editors...)
	})
}

func (c *Client) listShares(ctx context.Context, call func(context.Context, *string, ...controlv1.RequestEditorFn) (*http.Response, error)) ([]controlv1.Share, error) {
	var shares []controlv1.Share
	cursor := ""
	for {
		var next *string
		if cursor != "" {
			next = &cursor
		}
		page, err := requestWithAccess[controlv1.SharePage](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
			return call(ctx, next, editors...)
		})
		if err != nil {
			return nil, err
		}
		shares = append(shares, page.Shares...)
		if page.NextCursor == nil {
			return shares, nil
		}
		if len(page.Shares) == 0 || *page.NextCursor == cursor {
			return nil, failure.Wrap("list shares", failure.ServerResponseInvalid, errors.New("controlclient: invalid share cursor"))
		}
		cursor = *page.NextCursor
	}
}

func (c *Client) RevokeShare(ctx context.Context, id string) (controlv1.Share, error) {
	return requestWithAccess[controlv1.Share](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokeShare(ctx, id, editors...)
	})
}

func (c *Client) RedeemServiceShare(ctx context.Context, serviceID, runID string, body controlv1.RedeemServiceShareRequest, token credentials.ServiceRunToken) (controlv1.ShareRedemption, error) {
	return request[controlv1.ShareRedemption](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RedeemServiceShare(ctx, serviceID, runID, body, editors...)
	})
}

type controlRequest func(context.Context, ...controlv1.RequestEditorFn) (*http.Response, error)

func requestWithAccess[T any](ctx context.Context, client *Client, call controlRequest) (T, error) {
	access, err := client.currentAccessToken()
	if err != nil {
		var zero T
		return zero, err
	}
	return requestWithTimeout[T](ctx, client, client.timeout, access.String(), call)
}

func (c *Client) currentAccessToken() (credentials.AccessToken, error) {
	if c.externalAuthentication {
		return "", nil
	}
	if c.access == "" {
		return "", ErrUnauthenticated
	}
	return c.access, nil
}

func request[T any](ctx context.Context, client *Client, token string, call controlRequest) (T, error) {
	return requestWithTimeout[T](ctx, client, client.timeout, token, call)
}

func requestWithTimeout[T any](ctx context.Context, client *Client, timeout time.Duration, token string, call controlRequest) (T, error) {
	return requestWithTimeoutAndLimit[T](ctx, client, timeout, token, maxResponseBytes, call)
}

// a scoped operation may retain the original successful JSON and headers for a
// language binding. the ordinary generated request and decode path stays shared.
type controlResponseKey struct{}
type controlResponse struct {
	payload json.RawMessage
	header  http.Header
}

func requestWithTimeoutAndLimit[T any](ctx context.Context, client *Client, timeout time.Duration, token string, responseLimit int64, call controlRequest) (T, error) {
	var zero T
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	response, err := call(requestCtx, func(_ context.Context, request *http.Request) error {
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		return nil
	})
	if err != nil {
		return zero, unavailableError(ctx, err)
	}
	defer response.Body.Close()
	payload, err := httpjson.ReadAll(response.Body, responseLimit)
	if errors.Is(err, httpjson.ErrTooLarge) {
		return zero, failure.Wrap("read control response", failure.ServerResponseInvalid, errors.New("controlclient: response exceeds limit"))
	}
	if err != nil {
		return zero, unavailableError(ctx, err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return zero, responseError(response.StatusCode, response.Header, payload)
	}
	if response.StatusCode == http.StatusNoContent && len(payload) == 0 {
		return zero, nil
	}
	if len(payload) == 0 {
		return zero, failure.Wrap("read control response", failure.ServerResponseInvalid, errors.New("controlclient: successful response has an empty body"))
	}
	if bytes.Equal(bytes.TrimSpace(payload), []byte("null")) {
		return zero, failure.Wrap("read control response", failure.ServerResponseInvalid, errors.New("controlclient: successful response has a null body"))
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var result T
	err = httpjson.Decode(decoder, &result)
	if errors.Is(err, httpjson.ErrTrailingContent) {
		return zero, failure.Wrap("decode control response", failure.ServerResponseInvalid, errors.New("controlclient: response contains trailing JSON"))
	}
	if err != nil {
		return zero, failure.Wrap("decode control response", failure.ServerResponseInvalid, err)
	}
	if captured, ok := ctx.Value(controlResponseKey{}).(*controlResponse); ok {
		captured.payload, captured.header = payload, response.Header.Clone()
	}
	return result, nil
}

func unavailableError(ctx context.Context, err error) error {
	if cause := context.Cause(ctx); cause != nil {
		if failure.Only(err, cause) {
			return cause
		}
		return errors.Join(cause, err)
	}
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}

func responseError(status int, header http.Header, payload []byte) (result error) {
	var problem controlv1.Problem
	if json.Unmarshal(payload, &problem) != nil {
		return failure.Wrap("request control API", failure.ServerResponseInvalid, fmt.Errorf("controlclient: HTTP %d", status))
	}
	defer func() {
		var existing *ProblemError
		if !errors.As(result, &existing) {
			result = errors.Join(result, &ProblemError{Status: status, Problem: problem})
		}
	}()
	switch problem.Code {
	case controlv1.CredentialDeliveryUnavailable:
		return &ProblemError{Status: status, Problem: problem}
	case controlv1.ProjectManaged:
		return fmt.Errorf("%w: %w", ErrProjectManaged, &ProblemError{Status: status, Problem: problem})
	case controlv1.MemberHostnameDepthExceeded:
		return ErrMemberHostnameDepth
	case controlv1.Unauthenticated:
		return ErrUnauthenticated
	case controlv1.GuestTrialExhausted:
		return ErrGuestTrialExhausted
	case controlv1.GuestDemoOnly:
		return ErrGuestDemoOnly
	case controlv1.GuestIpChanged:
		return ErrGuestIPChanged
	case controlv1.GuestIssuanceLimited:
		return ErrGuestIssuanceLimited
	case controlv1.NotFound:
		cause := &ProblemError{Status: status, Problem: problem}
		if namespace, ok := serviceNamespace(cause); ok {
			return &ServiceNamespaceError{problem: cause, namespace: namespace}
		}
		return ErrNotFound
	case controlv1.NameUnavailable:
		return ErrNameUnavailable
	case controlv1.Conflict, controlv1.PolicyRevisionStale:
		return ErrStatusConflict
	case controlv1.DnsSetupPending:
		return ErrDNSProofPending
	case controlv1.IssuanceRetry:
		return ErrCertificateStatus
	case controlv1.RateLimited:
		seconds, err := strconv.ParseInt(header.Get("Retry-After"), 10, 64)
		if err != nil || seconds < 1 {
			seconds = 1
		}
		return &RateLimitError{RetryAfter: time.Duration(min(seconds, 86400)) * time.Second}
	case controlv1.Unavailable, controlv1.PlacementUnavailable:
		return ErrUnavailable
	case controlv1.Internal:
		return failure.Wrap("request control API", failure.ServerAPIInternal, &ProblemError{Status: status, Problem: problem})
	default:
		cause := &ProblemError{Status: status, Problem: problem}
		if status >= 500 && status < 600 {
			return failure.Wrap("request control API", failure.ServerAPIInternal, cause)
		}
		if status == http.StatusForbidden {
			return failure.Wrap("request control API", failure.ServerDenied, cause)
		}
		return failure.Wrap("request control API", failure.ServerRequestInvalid, cause)
	}
}

type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string { return "controlclient: rate limited" }
func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

type ProblemError struct {
	Status  int
	Problem controlv1.Problem
}

func (e *ProblemError) Error() string {
	if id, ok := e.CredentialDeliveryResourceID(); ok {
		return "credential delivery unavailable for " + id + "; revoke it, then create with a new key"
	}
	return "controlclient: HTTP " + strconv.Itoa(e.Status) + ": " + e.Problem.Title
}

func (e *ProblemError) CredentialDeliveryResourceID() (string, bool) {
	if e.Problem.Code == controlv1.CredentialDeliveryUnavailable && e.Problem.Details != nil {
		id, _ := (*e.Problem.Details)["resource_id"].(string)
		if opaqueid.Valid(id, opaqueid.SharePrefix) || opaqueid.Valid(id, opaqueid.ServiceInvitationPrefix) {
			return id, true
		}
	}
	return "", false
}
