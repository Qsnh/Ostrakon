// Package jev is a minimal client for TypeSafe's Jev decision model
// (POST /v1/systemone). It makes a single attempt per call; retry, backoff
// and pausing belong to the caller, guided by Classify.
package jev

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the production Jev endpoint.
	DefaultBaseURL = "https://api.typesafe.ai"
	// Model is pinned (never "latest") so vendor upgrades cannot silently
	// change behavior.
	Model = "jev-1.13.0"

	requestTimeout  = 10 * time.Second
	maxErrorBody    = 4 << 10 // bytes of an error response kept in APIError.Body
	maxResponseBody = 1 << 20 // bytes of a success response we are willing to read
	maxRetryAfter   = 24 * time.Hour
	systemOnePath   = "/v1/systemone"
)

// Question is one question put to Jev. Type is "noul", "choice" or "score".
type Question struct {
	Type         string `json:"type"`
	Instructions string `json:"instructions"`
	Criteria     any    `json:"criteria,omitempty"`
}

// Request is the body of POST /v1/systemone.
type Request struct {
	Model     string              `json:"model"`
	State     any                 `json:"state"`
	Questions map[string]Question `json:"questions"`
}

// Answer is Jev's answer to one question; which fields are set depends on Type.
type Answer struct {
	Type          string             `json:"type"`
	Noul          float64            `json:"noul"`
	Choice        string             `json:"choice"`
	Score         float64            `json:"score"`
	Probabilities map[string]float64 `json:"probabilities"`
	Confidence    float64            `json:"confidence"`
}

// Usage reports token consumption for one call.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// Response is the body of a successful POST /v1/systemone.
type Response struct {
	Model   string            `json:"model"`
	Answers map[string]Answer `json:"answers"`
	Usage   Usage             `json:"usage"`
}

// Client talks to Jev. Key is called once per SystemOne so a key rotated on
// disk takes effect without a restart.
type Client struct {
	BaseURL string
	Key     func() (string, error)
	HTTP    *http.Client
}

// New returns a Client with a 10s per-request timeout. An empty baseURL means
// DefaultBaseURL.
func New(baseURL string, key func() (string, error)) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		BaseURL: baseURL,
		Key:     key,
		HTTP:    &http.Client{Timeout: requestTimeout},
	}
}

// SystemOne sends req to Jev once. An empty req.Model is filled with Model.
//
// Errors, for Classify: a failing Key (such as apikey.ErrNoKey) is returned
// wrapped without sending anything; a non-2xx status is an *APIError; if ctx
// ends the error wraps ctx.Err(); other transport failures, including the
// client's own timeout while ctx is alive, are retryable; a 2xx body that is
// not valid JSON is a plain error.
func (c *Client) SystemOne(ctx context.Context, req Request) (Response, error) {
	key, err := c.Key()
	if err != nil {
		return Response{}, fmt.Errorf("jev: load API key: %w", err)
	}
	if req.Model == "" {
		req.Model = Model
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return Response{}, fmt.Errorf("jev: encode request: %w", err)
	}

	url := strings.TrimRight(c.BaseURL, "/") + systemOnePath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return Response{}, fmt.Errorf("jev: build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+key)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return Response{}, transportFailure(ctx, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Best effort: a body that fails to read is just a shorter message.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return Response{}, &APIError{
			Status:     resp.StatusCode,
			Body:       string(body),
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
		}
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return Response{}, transportFailure(ctx, err)
	}
	var out Response
	if err := json.Unmarshal(data, &out); err != nil {
		return Response{}, fmt.Errorf("jev: decode response: %w", err)
	}
	return out, nil
}

// transportFailure turns an error from the HTTP exchange into what Classify
// expects: if the caller's ctx is done, an error wrapping ctx.Err(); otherwise
// a retryable transport error.
func transportFailure(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("jev: request aborted: %w", ctxErr)
	}
	return &transportError{err: err}
}

// parseRetryAfter reads the integer-seconds form of Retry-After. Anything
// else (HTTP-date, negative, garbage, empty) is 0. Huge values are capped so
// the conversion to a Duration cannot overflow.
func parseRetryAfter(v string) time.Duration {
	secs, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || secs <= 0 {
		return 0
	}
	if secs > int(maxRetryAfter/time.Second) {
		return maxRetryAfter
	}
	return time.Duration(secs) * time.Second
}
