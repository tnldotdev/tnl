// package githubmetadata resolves immutable repository metadata during trusted
// apply. it reads existing gh authentication; it never starts a login flow.
package githubmetadata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"time"
)

type Repository struct {
	Repository   string
	RepositoryID string
	OwnerID      string
}

var repositoryName = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
var numericID = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

type MetadataError struct{ cause error }

func (e *MetadataError) Error() string {
	return "first ci apply needs GitHub repository metadata; configure existing gh authentication with read access to this repository, or have a trusted operator apply verified repository and owner IDs"
}
func (e *MetadataError) Unwrap() error { return e.cause }

func Resolve(ctx context.Context, repository string) (Repository, error) {
	if !repositoryName.MatchString(repository) {
		return Repository{}, &MetadataError{errors.New("invalid repository name")}
	}
	// gh api is read-only and uses whatever authentication is already installed.
	command := exec.CommandContext(ctx, "gh", "api", "--hostname", "github.com", "repos/"+repository)
	output, ghErr := command.Output()
	if ghErr == nil {
		return decode(output)
	}
	if context.Cause(ctx) != nil {
		return Repository{}, context.Cause(ctx)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+repository, nil)
	if err != nil {
		return Repository{}, &MetadataError{err}
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return Repository{}, &MetadataError{errors.Join(ghErr, err)}
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return Repository{}, &MetadataError{errors.Join(ghErr, fmt.Errorf("repository metadata HTTP status %d", response.StatusCode))}
	}
	output, err = io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(output) > 64<<10 {
		return Repository{}, &MetadataError{errors.Join(err, errors.New("repository metadata exceeds bounds"))}
	}
	return decode(output)
}

func decode(data []byte) (Repository, error) {
	var body struct {
		ID       json.Number `json:"id"`
		FullName string      `json:"full_name"`
		Owner    struct {
			ID json.Number `json:"id"`
		} `json:"owner"`
	}
	if len(data) > 64<<10 {
		return Repository{}, &MetadataError{errors.New("repository metadata exceeds bounds")}
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return Repository{}, &MetadataError{err}
	}
	if !repositoryName.MatchString(body.FullName) || !numericID.MatchString(body.ID.String()) || !numericID.MatchString(body.Owner.ID.String()) {
		return Repository{}, &MetadataError{errors.New("repository metadata is incomplete")}
	}
	return Repository{Repository: body.FullName, RepositoryID: body.ID.String(), OwnerID: body.Owner.ID.String()}, nil
}
