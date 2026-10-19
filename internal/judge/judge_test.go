package judge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"ostrakon/internal/event"
	"ostrakon/internal/jev"
)

var testIP = netip.MustParseAddr("203.0.113.7")

// asMap round-trips a request through JSON, which is what Jev receives.
func asMap(t *testing.T, req jev.Request) map[string]any {
	t.Helper()
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	return m
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func stateOf(t *testing.T, req jev.Request) map[string]any {
	t.Helper()
	st, ok := asMap(t, req)["state"].(map[string]any)
	if !ok {
		t.Fatalf("state is not an object: %#v", asMap(t, req)["state"])
	}
	return st
}

func stateEvents(t *testing.T, req jev.Request) []map[string]any {
	t.Helper()
	raw, ok := stateOf(t, req)["events"].([]any)
	if !ok {
		t.Fatalf("state.events is not an array: %#v", stateOf(t, req)["events"])
	}
	out := make([]map[string]any, len(raw))
	for i, r := range raw {
		out[i] = r.(map[string]any)
	}
	return out
}

func TestBuildRequestShape(t *testing.T) {
	base := time.Date(2026, 10, 18, 20, 0, 0, 0, time.UTC)
	events := make([]event.Event, 60)
	for i := range events {
		events[i] = event.Event{
			Time:   base.Add(time.Duration(i) * time.Second),
			Source: "nginx-access",
			IP:     testIP,
			Kind:   event.KindHTTPRequest,
			Method: "GET",
			Path:   fmt.Sprintf("/p%d", i),
			Status: 404,
		}
	}
	lastBan := time.Date(2026, 10, 17, 3, 4, 5, 0, time.UTC)
	req := BuildRequest(testIP, events, History{BanCount: 2, LastBan: lastBan})

	if req.Model != "jev-1.13.0" {
		t.Errorf("model = %q, want jev-1.13.0", req.Model)
	}
	m := asMap(t, req)
	if m["model"] != "jev-1.13.0" {
		t.Errorf("serialized model = %v", m["model"])
	}

	st := stateOf(t, req)
	if st["ip"] != "203.0.113.7" {
		t.Errorf("state.ip = %v", st["ip"])
	}
	hist := st["history"].(map[string]any)
	if hist["previous_bans"] != float64(2) {
		t.Errorf("history.previous_bans = %v, want 2", hist["previous_bans"])
	}
	if hist["last_ban"] != "2026-10-17T03:04:05Z" {
		t.Errorf("history.last_ban = %v", hist["last_ban"])
	}

	evs := stateEvents(t, req)
	if len(evs) != MaxEvents {
		t.Fatalf("len(state.events) = %d, want %d", len(evs), MaxEvents)
	}
	for i, ev := range evs {
		if want := fmt.Sprintf("/p%d", i+10); ev["path"] != want {
			t.Fatalf("events[%d].path = %v, want %s (the last %d events, in order)", i, ev["path"], want, MaxEvents)
		}
	}
	first := evs[0]
	if first["t"] != "2026-10-18T20:00:10Z" || first["source"] != "nginx-access" ||
		first["kind"] != "http_request" || first["method"] != "GET" || first["status"] != float64(404) {
		t.Errorf("events[0] = %v", first)
	}

	qs := sortedKeys(req.Questions)
	if want := []string{"ban_duration", "category", "is_attack"}; !reflect.DeepEqual(qs, want) {
		t.Fatalf("question keys = %v, want %v", qs, want)
	}
	if req.Questions["is_attack"].Type != "noul" {
		t.Errorf("is_attack type = %q, want noul", req.Questions["is_attack"].Type)
	}
	for name, want := range map[string][]string{
		"category":     {"benign", "other_malicious", "ssh_bruteforce", "web_bruteforce", "web_scan"},
		"ban_duration": {"10m", "1h", "24h", "7d", "none"},
	} {
		q := req.Questions[name]
		if q.Type != "choice" {
			t.Errorf("%s type = %q, want choice", name, q.Type)
		}
		crit, ok := q.Criteria.(map[string]string)
		if !ok {
			t.Fatalf("%s criteria is %T, want map[string]string", name, q.Criteria)
		}
		if got := sortedKeys(crit); !reflect.DeepEqual(got, want) {
			t.Errorf("%s criteria keys = %v, want %v", name, got, want)
		}
		for k, v := range crit {
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s criteria[%q] is empty", name, k)
			}
		}
	}
	for name, q := range req.Questions {
		if !strings.Contains(q.Instructions, "untrusted") {
			t.Errorf("%s instructions do not mention untrusted data: %q", name, q.Instructions)
		}
	}
	if !strings.Contains(req.Questions["ban_duration"].Instructions, "previous_bans") {
		t.Errorf("ban_duration instructions must tell Jev to weigh history.previous_bans")
	}
}

func TestBuildRequestFewEventsAndOmitEmpty(t *testing.T) {
	events := []event.Event{{
		Time:   time.Date(2026, 10, 18, 20, 0, 0, 0, time.UTC),
		Source: "sshd",
		IP:     testIP,
		Kind:   event.KindAuthFail,
		User:   "root",
	}}
	req := BuildRequest(testIP, events, History{})

	evs := stateEvents(t, req)
	if len(evs) != 1 {
		t.Fatalf("len(state.events) = %d, want 1", len(evs))
	}
	if got := sortedKeys(evs[0]); !reflect.DeepEqual(got, []string{"kind", "source", "t", "user"}) {
		t.Errorf("event keys = %v, want only the non-empty fields", got)
	}
	if evs[0]["user"] != "root" || evs[0]["kind"] != "auth_fail" || evs[0]["source"] != "sshd" {
		t.Errorf("event = %v", evs[0])
	}

	hist := stateOf(t, req)["history"].(map[string]any)
	if hist["previous_bans"] != float64(0) {
		t.Errorf("previous_bans = %v, want 0", hist["previous_bans"])
	}
	if v, present := hist["last_ban"]; !present || v != nil {
		t.Errorf("last_ban = %v (present=%v), want JSON null when there is no history", v, present)
	}
}

func TestBuildRequestNoEventsIsEmptyArray(t *testing.T) {
	req := BuildRequest(testIP, nil, History{})
	if evs := stateEvents(t, req); len(evs) != 0 {
		t.Errorf("events = %v, want empty array", evs)
	}
}

func TestBuildRequestUnmapsIP(t *testing.T) {
	req := BuildRequest(netip.MustParseAddr("::ffff:203.0.113.7"), nil, History{})
	if got := stateOf(t, req)["ip"]; got != "203.0.113.7" {
		t.Errorf("state.ip = %v, want 203.0.113.7", got)
	}
}

func TestBuildRequestDoesNotMutateEvents(t *testing.T) {
	events := []event.Event{{
		Time: time.Now(), Source: "sshd", IP: testIP, Kind: event.KindAuthFail,
		User: "a\x00b" + strings.Repeat("x", 500),
	}}
	orig := events[0]
	_ = BuildRequest(testIP, events, History{})
	if !reflect.DeepEqual(events[0], orig) {
		t.Errorf("BuildRequest mutated the caller's events: %#v", events[0])
	}
}

func TestTruncation(t *testing.T) {
	events := []event.Event{{
		Time:      time.Date(2026, 10, 18, 20, 0, 0, 0, time.UTC),
		Source:    "nginx-access",
		IP:        testIP,
		Kind:      event.KindHTTPRequest,
		User:      strings.Repeat("a", 10000) + "\xff\xfe",
		Method:    "GE\x00T",
		Path:      "/x\x00\x1b[31m" + strings.Repeat("世", 300),
		UserAgent: strings.Repeat("u", 200) + "\xc3",
		Status:    200,
	}}
	req := BuildRequest(testIP, events, History{})

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !utf8.Valid(data) {
		t.Fatalf("serialized request is not valid UTF-8")
	}

	ev := stateEvents(t, req)[0]
	for _, field := range []string{"user", "method", "path", "ua"} {
		s, ok := ev[field].(string)
		if !ok {
			t.Fatalf("event field %q missing or not a string: %v", field, ev[field])
		}
		if n := utf8.RuneCountInString(s); n > MaxField {
			t.Errorf("%s has %d runes, want <= %d", field, n, MaxField)
		}
		if !utf8.ValidString(s) {
			t.Errorf("%s is not valid UTF-8", field)
		}
		for _, r := range s {
			if r < 0x20 {
				t.Errorf("%s contains control character %U", field, r)
			}
		}
	}
	if got := ev["user"].(string); got != strings.Repeat("a", MaxField) {
		t.Errorf("user = %q, want %d 'a' runes", got, MaxField)
	}
	if got := ev["method"]; got != "GET" {
		t.Errorf("method = %q, want control characters removed", got)
	}
	if got := ev["path"].(string); !strings.HasPrefix(got, "/x[31m世") {
		t.Errorf("path = %q, want control characters removed, rest kept", got)
	}
}

func TestSanitizeInvalidUTF8BecomesReplacementChar(t *testing.T) {
	if got := sanitize("a\xffb"); got != "a�b" {
		t.Errorf("sanitize = %q, want replacement char", got)
	}
	// Truncation must not split a multi-byte rune.
	got := sanitize(strings.Repeat("é", MaxField+5))
	if utf8.RuneCountInString(got) != MaxField || !utf8.ValidString(got) {
		t.Errorf("sanitize kept %d runes (valid=%v)", utf8.RuneCountInString(got), utf8.ValidString(got))
	}
}

type fakeClient struct {
	resp jev.Response
	err  error
	got  []jev.Request
}

func (f *fakeClient) SystemOne(_ context.Context, req jev.Request) (jev.Response, error) {
	f.got = append(f.got, req)
	return f.resp, f.err
}

func answers(attack float64, category, duration string, inputTokens int) jev.Response {
	return jev.Response{
		Model: jev.Model,
		Answers: map[string]jev.Answer{
			"is_attack":    {Type: "noul", Noul: attack},
			"category":     {Type: "choice", Choice: category},
			"ban_duration": {Type: "choice", Choice: duration},
		},
		Usage: jev.Usage{InputTokens: inputTokens},
	}
}

func decide(t *testing.T, j *Judge) (Decision, error) {
	t.Helper()
	ev := []event.Event{{Time: time.Now(), Source: "sshd", IP: testIP, Kind: event.KindAuthFail, User: "root"}}
	return j.Decide(context.Background(), testIP, ev, History{})
}

func TestDecideBan(t *testing.T) {
	fc := &fakeClient{resp: answers(0.93, "ssh_bruteforce", "1h", 1834)}
	j := &Judge{Client: fc, Threshold: DefaultThreshold}

	got, err := decide(t, j)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	want := Decision{Ban: true, Duration: time.Hour, Category: "ssh_bruteforce", AttackProb: 0.93, InputTokens: 1834}
	if got != want {
		t.Errorf("Decision = %+v, want %+v", got, want)
	}
	if len(fc.got) != 1 || fc.got[0].Model != jev.Model || len(fc.got[0].Questions) != 3 {
		t.Errorf("client request = %+v", fc.got)
	}
}

func TestDecideDurationMapping(t *testing.T) {
	for label, want := range map[string]time.Duration{
		"10m": 10 * time.Minute,
		"1h":  time.Hour,
		"24h": 24 * time.Hour,
		"7d":  168 * time.Hour,
	} {
		t.Run(label, func(t *testing.T) {
			j := &Judge{Client: &fakeClient{resp: answers(0.9, "web_scan", label, 1)}, Threshold: DefaultThreshold}
			got, err := decide(t, j)
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if !got.Ban || got.Duration != want {
				t.Errorf("Decision = %+v, want Ban with duration %v", got, want)
			}
		})
	}
}

func TestDecideBelowThreshold(t *testing.T) {
	j := &Judge{Client: &fakeClient{resp: answers(0.79, "web_scan", "24h", 900)}, Threshold: DefaultThreshold}
	got, err := decide(t, j)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got.Ban || got.Duration != 0 {
		t.Errorf("Decision = %+v, want no ban and no duration", got)
	}
	if got.AttackProb != 0.79 || got.Category != "web_scan" || got.InputTokens != 900 {
		t.Errorf("Decision lost its diagnostic fields: %+v", got)
	}
}

func TestDecideAtThresholdBans(t *testing.T) {
	j := &Judge{Client: &fakeClient{resp: answers(0.8, "web_scan", "10m", 1)}, Threshold: 0.8}
	got, err := decide(t, j)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !got.Ban {
		t.Errorf("score equal to the threshold must ban: %+v", got)
	}
}

func TestDecideZeroThresholdUsesDefault(t *testing.T) {
	j := &Judge{Client: &fakeClient{resp: answers(0.5, "other_malicious", "1h", 1)}}
	got, err := decide(t, j)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got.Ban {
		t.Errorf("an unset Threshold must mean DefaultThreshold, not ban everything: %+v", got)
	}
}

func TestDecideNone(t *testing.T) {
	j := &Judge{Client: &fakeClient{resp: answers(0.95, "benign", "none", 1)}, Threshold: DefaultThreshold}
	got, err := decide(t, j)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if got.Ban || got.Duration != 0 {
		t.Errorf("Decision = %+v, want no ban", got)
	}
}

func TestDecideUnknownCategoryIsNotMalformed(t *testing.T) {
	for name, resp := range map[string]jev.Response{
		"unknown": answers(0.9, "something_else", "1h", 1),
		"missing": func() jev.Response {
			r := answers(0.9, "", "1h", 1)
			delete(r.Answers, "category")
			return r
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			j := &Judge{Client: &fakeClient{resp: resp}, Threshold: DefaultThreshold}
			got, err := decide(t, j)
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if !got.Ban || got.Duration != time.Hour || got.Category != "" {
				t.Errorf("Decision = %+v, want ban for 1h with empty category", got)
			}
		})
	}
}

func TestDecideMalformed(t *testing.T) {
	cases := map[string]func(r *jev.Response){
		"missing ban_duration": func(r *jev.Response) { delete(r.Answers, "ban_duration") },
		"forever":              func(r *jev.Response) { r.Answers["ban_duration"] = jev.Answer{Type: "choice", Choice: "forever"} },
		"empty choice":         func(r *jev.Response) { r.Answers["ban_duration"] = jev.Answer{Type: "choice"} },
		"missing is_attack":    func(r *jev.Response) { delete(r.Answers, "is_attack") },
		"is_attack above 1":    func(r *jev.Response) { r.Answers["is_attack"] = jev.Answer{Type: "noul", Noul: 1.5} },
		"is_attack negative":   func(r *jev.Response) { r.Answers["is_attack"] = jev.Answer{Type: "noul", Noul: -0.1} },
		"no answers":           func(r *jev.Response) { r.Answers = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			resp := answers(0.99, "ssh_bruteforce", "7d", 1)
			mutate(&resp)
			j := &Judge{Client: &fakeClient{resp: resp}, Threshold: DefaultThreshold}
			got, err := decide(t, j)
			if got.Ban {
				t.Errorf("a malformed answer must never ban: %+v", got)
			}
			if !errors.Is(err, ErrMalformedAnswer) {
				t.Fatalf("err = %v, want ErrMalformedAnswer", err)
			}
			if c := jev.Classify(err); c != jev.ClassBadRequest {
				t.Errorf("Classify = %v, want ClassBadRequest", c)
			}
		})
	}
}

func TestDecideClientError(t *testing.T) {
	j := &Judge{Client: &fakeClient{err: &jev.APIError{Status: 529}}, Threshold: DefaultThreshold}
	got, err := decide(t, j)
	if got.Ban {
		t.Errorf("a failed call must not ban: %+v", got)
	}
	var apiErr *jev.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 529 {
		t.Fatalf("err = %v, want the *jev.APIError{529} back", err)
	}
	if jev.Classify(err) != jev.ClassRetryable {
		t.Errorf("Classify = %v, want ClassRetryable", jev.Classify(err))
	}
}

func TestPingRequest(t *testing.T) {
	req := PingRequest()
	if req.Model != jev.Model {
		t.Errorf("model = %q", req.Model)
	}
	if req.State != "ping" {
		t.Errorf("state = %#v, want \"ping\"", req.State)
	}
	if len(req.Questions) != 1 || req.Questions["ok"].Type != "noul" || req.Questions["ok"].Instructions == "" {
		t.Errorf("questions = %+v, want one noul question \"ok\"", req.Questions)
	}
	if _, err := json.Marshal(req); err != nil {
		t.Errorf("json.Marshal: %v", err)
	}
}
