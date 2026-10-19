package jev

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Qsnh/Ostrakon/internal/apikey"
)

const okBody = `{"model":"jev-1.13.0","answers":{"is_attack":{"type":"noul","noul":0.93},"ban_duration":{"type":"choice","choice":"1h","probabilities":{"1h":0.7,"none":0.3},"confidence":0.7}},"usage":{"input_tokens":1834,"output_tokens":0}}`

func staticKey(k string) func() (string, error) {
	return func() (string, error) { return k, nil }
}

func sampleRequest() Request {
	return Request{
		Model: Model,
		State: map[string]any{"ip": "203.0.113.9"},
		Questions: map[string]Question{
			"is_attack": {Type: "noul", Instructions: "Is this IP attacking?"},
		},
	}
}

// hitCounter wraps a handler and counts the requests that reach it.
type hitCounter struct {
	mu sync.Mutex
	n  int
}

func (h *hitCounter) wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.n++
		h.mu.Unlock()
		next(w, r)
	}
}

func (h *hitCounter) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.n
}

func TestSystemOneSendsRequest(t *testing.T) {
	var (
		gotMethod, gotPath, gotAuth, gotCT string
		gotBody                            map[string]any
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotAuth, gotCT = r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("server could not decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, okBody)
	}))
	defer srv.Close()

	c := New(srv.URL, staticKey("k-123"))
	resp, err := c.SystemOne(context.Background(), sampleRequest())
	if err != nil {
		t.Fatalf("SystemOne: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/v1/systemone" {
		t.Errorf("path = %q, want /v1/systemone", gotPath)
	}
	if gotAuth != "Bearer k-123" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer k-123")
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if gotBody["model"] != "jev-1.13.0" {
		t.Errorf("body model = %v, want jev-1.13.0", gotBody["model"])
	}
	qs, _ := gotBody["questions"].(map[string]any)
	isAttack, _ := qs["is_attack"].(map[string]any)
	if isAttack["type"] != "noul" {
		t.Errorf("body questions.is_attack.type = %v, want noul", isAttack["type"])
	}
	if _, ok := gotBody["state"]; !ok {
		t.Errorf("body has no state field: %v", gotBody)
	}

	if resp.Model != "jev-1.13.0" {
		t.Errorf("resp.Model = %q", resp.Model)
	}
	if got := resp.Answers["is_attack"].Noul; got == nil || *got != 0.93 {
		t.Errorf("is_attack noul = %v, want 0.93", got)
	}
	bd := resp.Answers["ban_duration"]
	if bd.Choice != "1h" || bd.Probabilities["1h"] != 0.7 || bd.Confidence != 0.7 {
		t.Errorf("ban_duration = %+v, want choice 1h, p(1h)=0.7, confidence 0.7", bd)
	}
	if resp.Usage.InputTokens != 1834 || resp.Usage.OutputTokens != 0 {
		t.Errorf("usage = %+v, want input 1834 output 0", resp.Usage)
	}
}

func TestSystemOneDefaultsModel(t *testing.T) {
	var gotModel any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotModel = body["model"]
		_, _ = io.WriteString(w, okBody)
	}))
	defer srv.Close()

	req := sampleRequest()
	req.Model = ""
	if _, err := New(srv.URL, staticKey("k")).SystemOne(context.Background(), req); err != nil {
		t.Fatalf("SystemOne: %v", err)
	}
	if gotModel != Model {
		t.Errorf("model sent = %v, want default %q", gotModel, Model)
	}
}

func TestSystemOneBaseURLTrailingSlash(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, okBody)
	}))
	defer srv.Close()

	if _, err := New(srv.URL+"/", staticKey("k")).SystemOne(context.Background(), sampleRequest()); err != nil {
		t.Fatalf("SystemOne: %v", err)
	}
	if gotPath != "/v1/systemone" {
		t.Errorf("path = %q, want /v1/systemone (no double slash)", gotPath)
	}
}

func TestKeyReadOncePerCall(t *testing.T) {
	var (
		mu    sync.Mutex
		auths []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auths = append(auths, r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = io.WriteString(w, okBody)
	}))
	defer srv.Close()

	calls := 0
	key := func() (string, error) {
		calls++
		return "rot-" + strconv.Itoa(calls), nil
	}
	c := New(srv.URL, key)
	for i := 0; i < 2; i++ {
		if _, err := c.SystemOne(context.Background(), sampleRequest()); err != nil {
			t.Fatalf("SystemOne #%d: %v", i+1, err)
		}
	}

	if calls != 2 {
		t.Errorf("Key called %d times for 2 SystemOne calls, want 2", calls)
	}
	want := []string{"Bearer rot-1", "Bearer rot-2"}
	if strings.Join(auths, "|") != strings.Join(want, "|") {
		t.Errorf("Authorization headers = %v, want %v", auths, want)
	}
}

func TestErrorClassification(t *testing.T) {
	tests := []struct {
		status         int
		retryAfter     string
		want           Class
		wantRetryAfter time.Duration
	}{
		{status: 401, want: ClassAuth},
		{status: 402, want: ClassAuth},
		{status: 403, want: ClassAuth},
		{status: 404, want: ClassAuth},
		{status: 405, want: ClassAuth},
		{status: 410, want: ClassAuth},
		{status: 429, retryAfter: "7", want: ClassRetryable, wantRetryAfter: 7 * time.Second},
		{status: 429, want: ClassRetryable},
		{status: 529, want: ClassRetryable},
		{status: 500, want: ClassRetryable},
		{status: 503, want: ClassRetryable},
		{status: 408, want: ClassRetryable},
		{status: 425, want: ClassRetryable},
		{status: 418, want: ClassRetryable}, // any other 4xx
		{status: 400, want: ClassBadRequest},
		{status: 413, want: ClassBadRequest},
		{status: 415, want: ClassBadRequest},
		{status: 422, want: ClassBadRequest},
	}

	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.status), func(t *testing.T) {
			hits := &hitCounter{}
			srv := httptest.NewServer(hits.wrap(func(w http.ResponseWriter, r *http.Request) {
				if tt.retryAfter != "" {
					w.Header().Set("Retry-After", tt.retryAfter)
				}
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, `{"error":"boom"}`)
			}))
			defer srv.Close()

			_, err := New(srv.URL, staticKey("k")).SystemOne(context.Background(), sampleRequest())
			if err == nil {
				t.Fatal("SystemOne succeeded, want an error")
			}
			if got := Classify(err); got != tt.want {
				t.Errorf("Classify = %d, want %d (err: %v)", got, tt.want, err)
			}

			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("err = %T %v, want it to wrap *APIError", err, err)
			}
			if apiErr.Status != tt.status {
				t.Errorf("APIError.Status = %d, want %d", apiErr.Status, tt.status)
			}
			if apiErr.Body != `{"error":"boom"}` {
				t.Errorf("APIError.Body = %q", apiErr.Body)
			}
			if apiErr.RetryAfter != tt.wantRetryAfter {
				t.Errorf("APIError.RetryAfter = %v, want %v", apiErr.RetryAfter, tt.wantRetryAfter)
			}
			if hits.count() != 1 {
				t.Errorf("server saw %d requests, want exactly 1 (no internal retry)", hits.count())
			}
		})
	}
}

func TestAPIErrorBodyIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, strings.Repeat("x", 200*1024))
	}))
	defer srv.Close()

	_, err := New(srv.URL, staticKey("k")).SystemOne(context.Background(), sampleRequest())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *APIError", err)
	}
	if len(apiErr.Body) == 0 || len(apiErr.Body) > 4096 {
		t.Errorf("len(APIError.Body) = %d, want 1..4096", len(apiErr.Body))
	}
}

func TestAPIErrorMessage(t *testing.T) {
	long := &APIError{Status: 502, Body: "line one\nline two\n" + strings.Repeat("y", 5000)}
	msg := long.Error()
	if !strings.Contains(msg, "502") {
		t.Errorf("Error() = %q, want it to contain the status", msg)
	}
	if strings.ContainsAny(msg, "\r\n") {
		t.Errorf("Error() = %q, want a single line", msg)
	}
	if len(msg) > 400 {
		t.Errorf("len(Error()) = %d, want a short log-friendly message", len(msg))
	}

	empty := &APIError{Status: 401}
	if !strings.Contains(empty.Error(), "401") {
		t.Errorf("Error() = %q, want it to contain the status", empty.Error())
	}
}

func TestParseRetryAfter(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"7", 7 * time.Second},
		{" 30 ", 30 * time.Second},
		{"0", 0},
		{"", 0},
		{"-5", 0},
		{"1.5", 0},
		{"abc", 0},
		{"Wed, 21 Oct 2015 07:28:00 GMT", 0}, // HTTP-date form is not supported
		{"99999999999999999999", 0},          // does not fit an int
		{"9223372036854775807", maxRetryAfter},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := parseRetryAfter(tt.in); got != tt.want {
				t.Errorf("parseRetryAfter(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestNetworkErrorRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	base := srv.URL
	srv.Close() // nothing listens on this address any more

	_, err := New(base, staticKey("k")).SystemOne(context.Background(), sampleRequest())
	if err == nil {
		t.Fatal("SystemOne succeeded against a closed server")
	}
	if got := Classify(err); got != ClassRetryable {
		t.Errorf("Classify = %d, want ClassRetryable (err: %v)", got, err)
	}
}

func TestHTTPClientTimeoutIsRetryableNotCanceled(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	c := New(srv.URL, staticKey("k"))
	c.HTTP.Timeout = 50 * time.Millisecond

	// The caller's ctx stays alive, so the client-side timeout is a transport
	// failure, even though net/http reports it as a deadline-exceeded error.
	_, err := c.SystemOne(context.Background(), sampleRequest())
	if err == nil {
		t.Fatal("SystemOne succeeded against a hanging server")
	}
	if got := Classify(err); got != ClassRetryable {
		t.Errorf("Classify = %d, want ClassRetryable (err: %v)", got, err)
	}
}

func TestTruncatedSuccessBodyIsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "500")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"model":"jev-1`)
	}))
	defer srv.Close()

	_, err := New(srv.URL, staticKey("k")).SystemOne(context.Background(), sampleRequest())
	if err == nil {
		t.Fatal("SystemOne succeeded on a truncated body")
	}
	if got := Classify(err); got != ClassRetryable {
		t.Errorf("Classify = %d, want ClassRetryable (err: %v)", got, err)
	}
}

func TestUndecodableSuccessBodyIsRetryable(t *testing.T) {
	// Persistent garbage from the endpoint means Jev is unusable, which must
	// lead to a visible pause rather than silently dropped decisions.
	tests := []struct {
		name string
		body string
	}{
		{"html page", "<html>oops</html>"},
		{"empty", ""},
		{"wrong shape", `{"answers":"nope"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, tt.body)
			}))
			defer srv.Close()

			_, err := New(srv.URL, staticKey("k")).SystemOne(context.Background(), sampleRequest())
			if err == nil {
				t.Fatal("SystemOne succeeded on an undecodable body")
			}
			if got := Classify(err); got != ClassRetryable {
				t.Errorf("Classify = %d, want ClassRetryable (err: %v)", got, err)
			}
		})
	}
}

func TestOddButDecodableAnswersAreReturned(t *testing.T) {
	// Valid JSON with missing or unexpected answers is the judge's problem
	// (judge.ErrMalformedAnswer), not a client error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"model":"jev-1.13.0","answers":{"ban_duration":{"type":"choice","choice":"forever"}}}`)
	}))
	defer srv.Close()

	resp, err := New(srv.URL, staticKey("k")).SystemOne(context.Background(), sampleRequest())
	if err != nil {
		t.Fatalf("SystemOne: %v", err)
	}
	if got := resp.Answers["ban_duration"].Choice; got != "forever" {
		t.Errorf("choice = %q, want %q passed through untouched", got, "forever")
	}
	if _, ok := resp.Answers["is_attack"]; ok {
		t.Error("is_attack answer appeared out of nowhere")
	}
}

func TestNoKey(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"bare", apikey.ErrNoKey},
		{"wrapped", fmt.Errorf("reading key: %w", apikey.ErrNoKey)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hits := &hitCounter{}
			srv := httptest.NewServer(hits.wrap(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, okBody)
			}))
			defer srv.Close()

			c := New(srv.URL, func() (string, error) { return "", tt.err })
			_, err := c.SystemOne(context.Background(), sampleRequest())
			if err == nil {
				t.Fatal("SystemOne succeeded without a key")
			}
			if !errors.Is(err, apikey.ErrNoKey) {
				t.Errorf("err = %v, want errors.Is apikey.ErrNoKey", err)
			}
			if got := Classify(err); got != ClassAuth {
				t.Errorf("Classify = %d, want ClassAuth", got)
			}
			if hits.count() != 0 {
				t.Errorf("server saw %d requests, want none when there is no key", hits.count())
			}
		})
	}
}

func TestCanceled(t *testing.T) {
	hits := &hitCounter{}
	srv := httptest.NewServer(hits.wrap(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, okBody)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := New(srv.URL, staticKey("k")).SystemOne(ctx, sampleRequest())
	if err == nil {
		t.Fatal("SystemOne succeeded with a canceled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want errors.Is context.Canceled", err)
	}
	if got := Classify(err); got != ClassCanceled {
		t.Errorf("Classify = %d, want ClassCanceled", got)
	}
	if hits.count() != 0 {
		t.Errorf("server saw %d requests with an already-canceled ctx, want none", hits.count())
	}
}

func TestCallerDeadlineIsCanceled(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := New(srv.URL, staticKey("k")).SystemOne(ctx, sampleRequest())
	if err == nil {
		t.Fatal("SystemOne succeeded against a hanging server")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want errors.Is context.DeadlineExceeded", err)
	}
	if got := Classify(err); got != ClassCanceled {
		t.Errorf("Classify = %d, want ClassCanceled", got)
	}
}

func TestCancelMidFlight(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-started
		cancel()
	}()

	_, err := New(srv.URL, staticKey("k")).SystemOne(ctx, sampleRequest())
	if got := Classify(err); got != ClassCanceled {
		t.Errorf("Classify = %d, want ClassCanceled (err: %v)", got, err)
	}
}

func TestClassify(t *testing.T) {
	netErr := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	urlErr := &url.Error{Op: "Post", URL: "https://api.typesafe.ai/v1/systemone", Err: errors.New("EOF")}

	tests := []struct {
		name string
		err  error
		want Class
	}{
		{"401", &APIError{Status: 401}, ClassAuth},
		{"402 billing", &APIError{Status: 402}, ClassAuth},
		{"403 forbidden", &APIError{Status: 403}, ClassAuth},
		{"404 wrong endpoint", &APIError{Status: 404}, ClassAuth},
		{"405", &APIError{Status: 405}, ClassAuth},
		{"410 gone", &APIError{Status: 410}, ClassAuth},
		{"408", &APIError{Status: 408}, ClassRetryable},
		{"425", &APIError{Status: 425}, ClassRetryable},
		{"429", &APIError{Status: 429}, ClassRetryable},
		{"529", &APIError{Status: 529}, ClassRetryable},
		{"500", &APIError{Status: 500}, ClassRetryable},
		{"599", &APIError{Status: 599}, ClassRetryable},
		{"other 4xx", &APIError{Status: 418}, ClassRetryable},
		{"unexpected 3xx", &APIError{Status: 302}, ClassRetryable},
		{"400", &APIError{Status: 400}, ClassBadRequest},
		{"413", &APIError{Status: 413}, ClassBadRequest},
		{"415", &APIError{Status: 415}, ClassBadRequest},
		{"422", &APIError{Status: 422}, ClassBadRequest},
		{"wrapped APIError", fmt.Errorf("judge: %w", &APIError{Status: 503}), ClassRetryable},
		{"ErrNoKey", apikey.ErrNoKey, ClassAuth},
		{"wrapped ErrNoKey", fmt.Errorf("x: %w", apikey.ErrNoKey), ClassAuth},
		{"context.Canceled", context.Canceled, ClassCanceled},
		{"wrapped Canceled", fmt.Errorf("x: %w", context.Canceled), ClassCanceled},
		{"context.DeadlineExceeded", context.DeadlineExceeded, ClassCanceled},
		{"wrapped DeadlineExceeded", fmt.Errorf("x: %w", context.DeadlineExceeded), ClassCanceled},
		{"net.Error", netErr, ClassRetryable},
		{"wrapped net.Error", fmt.Errorf("x: %w", netErr), ClassRetryable},
		{"url.Error", urlErr, ClassRetryable},
		{"transport error wrapping a deadline", &transportError{err: context.DeadlineExceeded}, ClassRetryable},
		{"plain error", errors.New("boom"), ClassBadRequest},
		// judge.ErrMalformedAnswer is a plain errors.New and must land here.
		{"malformed answer", fmt.Errorf("decide: %w", errors.New("jev: malformed answer")), ClassBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.err); got != tt.want {
				t.Errorf("Classify(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

func TestNewDefaults(t *testing.T) {
	c := New("https://example.test", staticKey("k"))
	if c.BaseURL != "https://example.test" {
		t.Errorf("BaseURL = %q", c.BaseURL)
	}
	if c.HTTP == nil || c.HTTP.Timeout != 10*time.Second {
		t.Errorf("HTTP client = %+v, want a 10s timeout", c.HTTP)
	}
	if got := New("", staticKey("k")).BaseURL; got != DefaultBaseURL {
		t.Errorf("empty base URL became %q, want DefaultBaseURL %q", got, DefaultBaseURL)
	}
}
