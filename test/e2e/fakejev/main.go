// Command fakejev is a stand-in for TypeSafe's Jev API, used by the
// end-to-end test. It listens on 127.0.0.1:8099 and answers
// POST /v1/systemone according to its current mode, which POST /mode
// switches (body: attack, benign, unauthorized or down; initially attack).
//
// `fakejev mode <name>` is the client side: it switches a running fakejev's
// mode and exits non-zero if that failed, so the test needs no curl.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"strings"
	"sync"
)

const (
	addr     = "127.0.0.1:8099"
	jevModel = "jev-1.13.0"
	maxBody  = 1 << 20
)

// answers maps each answering mode to its response body.
var answers = map[string]string{
	"attack": `{"model":"jev-1.13.0","answers":{` +
		`"is_attack":{"type":"noul","noul":0.97},` +
		`"category":{"type":"choice","choice":"ssh_bruteforce"},` +
		`"ban_duration":{"type":"choice","choice":"1h"}},` +
		`"usage":{"input_tokens":100,"output_tokens":0}}`,
	"benign": `{"model":"jev-1.13.0","answers":{` +
		`"is_attack":{"type":"noul","noul":0.05},` +
		`"category":{"type":"choice","choice":"benign"},` +
		`"ban_duration":{"type":"choice","choice":"none"}},` +
		`"usage":{"input_tokens":100,"output_tokens":0}}`,
}

// failures maps each failing mode to its HTTP status.
var failures = map[string]int{
	"unauthorized": http.StatusUnauthorized,
	"down":         http.StatusServiceUnavailable,
}

func validMode(m string) bool {
	_, ok := answers[m]
	_, bad := failures[m]
	return ok || bad
}

type server struct {
	mu   sync.Mutex
	mode string
}

func (s *server) current() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mode
}

func (s *server) setMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	m := strings.TrimSpace(string(body))
	if !validMode(m) {
		http.Error(w, fmt.Sprintf("unknown mode %q", m), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.mode = m
	s.mu.Unlock()
	log.Printf("mode set to %s", m)
	fmt.Fprintln(w, m)
}

// systemOne checks the request the way the real API would (method, bearer
// token, JSON body naming the pinned model and at least one question), then
// answers according to the current mode.
func (s *server) systemOne(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || strings.TrimSpace(token) == "" {
		log.Printf("systemone: missing bearer token -> 401")
		http.Error(w, `{"error":"missing bearer token"}`, http.StatusUnauthorized)
		return
	}
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		log.Printf("systemone: content type %q -> 415", r.Header.Get("Content-Type"))
		http.Error(w, `{"error":"content type must be application/json"}`, http.StatusUnsupportedMediaType)
		return
	}
	var req struct {
		Model     string                     `json:"model"`
		State     json.RawMessage            `json:"state"` // any JSON value, as in the real API
		Questions map[string]json.RawMessage `json:"questions"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&req); err != nil ||
		req.Model != jevModel || len(req.State) == 0 || len(req.Questions) == 0 {
		log.Printf("systemone: bad request (model %q, state %q, %d questions, err %v) -> 400",
			req.Model, req.State, len(req.Questions), err)
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	// For the log only: decisions carry {"ip": ...}; the ping's state is a string.
	var st struct {
		IP string `json:"ip"`
	}
	if json.Unmarshal(req.State, &st) != nil {
		st.IP = "-"
	}

	mode := s.current()
	if status, failing := failures[mode]; failing {
		log.Printf("systemone: ip=%q questions=%d mode=%s -> %d", st.IP, len(req.Questions), mode, status)
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, mode), status)
		return
	}
	log.Printf("systemone: ip=%q questions=%d mode=%s -> 200", st.IP, len(req.Questions), mode)
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, answers[mode])
}

func serve() error {
	s := &server{mode: "attack"}
	mux := http.NewServeMux()
	mux.HandleFunc("/mode", s.setMode)
	mux.HandleFunc("/v1/systemone", s.systemOne)
	log.Printf("fake Jev listening on %s (mode attack)", addr)
	return http.ListenAndServe(addr, mux)
}

func switchMode(m string) error {
	resp, err := http.Post("http://"+addr+"/mode", "text/plain", strings.NewReader(m))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	switch {
	case len(os.Args) == 1:
		log.Fatal(serve())
	case len(os.Args) == 3 && os.Args[1] == "mode":
		if err := switchMode(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "fakejev: set mode %s: %v\n", os.Args[2], err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: fakejev | fakejev mode attack|benign|unauthorized|down")
		os.Exit(2)
	}
}
