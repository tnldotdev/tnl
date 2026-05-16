package tailbench

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type AgentClient struct {
	url   string
	token string
	http  *http.Client
}

func NewAgentClient(url, token string, timeout time.Duration) *AgentClient {
	return &AgentClient{
		url:   strings.TrimRight(url, "/"),
		token: token,
		http:  &http.Client{Timeout: timeout},
	}
}

func (a *AgentClient) Create(keys []string) (CreateRunResponse, error) {
	var response CreateRunResponse
	err := a.request(http.MethodPost, CreateRunRequest{ClientPublicKeys: keys}, &response)
	return response, err
}

func (a *AgentClient) Close() (CloseRunResponse, error) {
	var response CloseRunResponse
	err := a.request(http.MethodDelete, nil, &response)
	return response, err
}

func (a *AgentClient) request(method string, body, response any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, a.url+"/v1/run", reader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+a.token)
	request.Header.Set("Content-Type", "application/json")
	result, err := a.http.Do(request)
	if err != nil {
		return err
	}
	defer result.Body.Close()
	if result.StatusCode/100 != 2 {
		message, _ := io.ReadAll(io.LimitReader(result.Body, 4*1024))
		return fmt.Errorf("agent %s: %s: %s", method, result.Status, bytes.TrimSpace(message))
	}
	return json.NewDecoder(result.Body).Decode(response)
}
