package control

import (
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"strconv"

	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// the language adapter carries operation inputs, not another HTTP contract.
// requests use the existing generated Go API operations and error boundary.
type DeploymentManagementRequest struct {
	Operation      string          `json:"operation"`
	Deployment     string          `json:"deployment,omitempty"`
	Publisher      string          `json:"publisher,omitempty"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	IfMatch        string          `json:"if_match,omitempty"`
	After          string          `json:"after,omitempty"`
	Limit          int             `json:"limit,omitempty"`
	Body           json.RawMessage `json:"body,omitempty"`
}

func (DeploymentManagementRequest) String() string   { return "private deployment management request" }
func (DeploymentManagementRequest) GoString() string { return "private deployment management request" }

type DeploymentManagementResult struct {
	Schema  int                `json:"schema"`
	Data    any                `json:"data,omitempty"`
	ETag    string             `json:"etag,omitempty"`
	Status  int                `json:"status,omitempty"`
	Problem *controlv1.Problem `json:"problem,omitempty"`
}

func (DeploymentManagementResult) String() string   { return "private deployment management result" }
func (DeploymentManagementResult) GoString() string { return "private deployment management result" }

var ErrDeploymentManagementRequest = failure.Wrap("select deployment management operation", failure.ServerRequestInvalid, errors.New("invalid deployment management request"))

func (c *Client) ManageDeployment(ctx context.Context, team, project string, r DeploymentManagementRequest) (DeploymentManagementResult, error) {
	captured := new(controlResponse)
	ctx = context.WithValue(ctx, controlResponseKey{}, captured)
	result := DeploymentManagementResult{Schema: 1}
	var err error
	var revision int64
	if r.Operation == "deployments.update" || r.Operation == "deployments.delete" {
		condition, parseErr := strconv.Unquote(r.IfMatch)
		if parseErr != nil || strconv.Quote(condition) != r.IfMatch {
			return result, ErrDeploymentManagementRequest
		}
		revision, parseErr = strconv.ParseInt(condition, 10, 64)
		if parseErr != nil || revision < 1 || strconv.Quote(strconv.FormatInt(revision, 10)) != r.IfMatch {
			return result, ErrDeploymentManagementRequest
		}
	}
	if r.Limit == 0 {
		r.Limit = 50
	}
	if r.Limit < 1 || r.Limit > 100 {
		return result, ErrDeploymentManagementRequest
	}
	var deployment *controlv1.Deployment
	switch r.Operation {
	case "deployments.create":
		var body controlv1.CreateDeploymentRequest
		if jsonv2.Unmarshal(r.Body, &body, jsonv2.RejectUnknownMembers(true)) != nil || r.IdempotencyKey == "" {
			return result, ErrDeploymentManagementRequest
		}
		var value controlv1.Deployment
		value, err = c.CreateDeployment(ctx, team, project, r.IdempotencyKey, body)
		deployment = &value
	case "deployments.list":
		result.Data, err = c.ListDeployments(ctx, team, project, r.After, r.Limit)
	case "deployments.get":
		var value controlv1.Deployment
		value, err = c.GetDeployment(ctx, team, project, r.Deployment)
		deployment = &value
	case "deployments.update":
		var body controlv1.UpdateDeploymentRequest
		if jsonv2.Unmarshal(r.Body, &body, jsonv2.RejectUnknownMembers(true)) != nil {
			return result, ErrDeploymentManagementRequest
		}
		var value controlv1.Deployment
		value, err = c.UpdateDeployment(ctx, team, project, r.Deployment, revision, body)
		deployment = &value
	case "deployments.delete":
		err = c.DeleteDeployment(ctx, team, project, r.Deployment, revision)
	case "publishers.create_enrollment":
		var body controlv1.CreateDeploymentPublisherEnrollmentRequest
		if jsonv2.Unmarshal(r.Body, &body, jsonv2.RejectUnknownMembers(true)) != nil || r.IdempotencyKey == "" {
			return result, ErrDeploymentManagementRequest
		}
		result.Data, err = c.CreateDeploymentPublisherEnrollment(ctx, team, project, r.Deployment, r.IdempotencyKey, body)
	case "publishers.list":
		result.Data, err = c.ListDeploymentPublishers(ctx, team, project, r.Deployment, r.After, r.Limit)
	case "publishers.get":
		result.Data, err = c.GetDeploymentPublisher(ctx, team, project, r.Deployment, r.Publisher)
	case "publishers.revoke":
		err = c.RevokeDeploymentPublisher(ctx, team, project, r.Deployment, r.Publisher)
	default:
		return result, ErrDeploymentManagementRequest
	}
	if err != nil {
		var problem *ProblemError
		if errors.As(err, &problem) {
			return DeploymentManagementResult{Schema: 1, Status: problem.Status, Problem: &problem.Problem}, nil
		}
		return DeploymentManagementResult{}, err
	}
	if deployment != nil {
		if deployment.TeamId != team || deployment.ProjectKey != project || deployment.Revision < 1 {
			return DeploymentManagementResult{}, failure.Wrap("read deployment management result", failure.ServerResponseInvalid, errors.New("control returned another or invalid deployment"))
		}
		result.ETag = captured.header.Get("ETag")
		if result.ETag != strconv.Quote(strconv.FormatInt(deployment.Revision, 10)) {
			return DeploymentManagementResult{}, failure.Wrap("read deployment management result", failure.ServerResponseInvalid, errors.New("control returned an invalid deployment ETag"))
		}
	}
	// retain the canonical JSON, including required-field presence and unknown
	// fields, for generated-model validation in the calling language.
	result.Data = captured.payload
	return result, nil
}
