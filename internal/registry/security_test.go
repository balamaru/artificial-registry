package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdvisoryQuery(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		wantErr    bool
		findings   int
	}{
		{"clean", `{"results":[{}]}`, 200, false, 0},
		{"vulnerable", `{"results":[{"vulns":[{"id":"TEST-2026-001"}]}]}`, 200, false, 1},
		{"pagination", `{"results":[{"next_page_token":"next"}]}`, 200, false, 1},
		{"incomplete", `{"results":[]}`, 200, true, 0},
		{"outage", `{}`, 503, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var payload struct {
					Queries []struct {
						Version string
						Package struct{ Name, Ecosystem string }
					}
				}
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || len(payload.Queries) != 1 || payload.Queries[0].Package.Ecosystem != "PyPI" || payload.Queries[0].Version != "1.0.0" {
					t.Error("invalid OSV request")
				}
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer server.Close()
			findings, err := queryOSV(context.Background(), server.URL, []dependency{{"example", "PyPI", "1.0.0"}})
			if (err != nil) != tc.wantErr || len(findings) != tc.findings {
				t.Fatalf("findings=%v err=%v", findings, err)
			}
		})
	}
}
func TestDependencyParsing(t *testing.T) {
	for _, tc := range []struct {
		name, body   string
		deps, issues int
	}{
		{"requirements.txt", "requests==2.31.0\nflask>=1\n", 1, 1},
		{"go.mod", "module example.org/skill\nrequire (\n example.org/lib v1.2.3\n)\n", 1, 0},
		{"package-lock.json", `{"lockfileVersion":3,"packages":{"":{},"node_modules/@scope/pkg":{"version":"1.2.3"}}}`, 1, 0},
		{"package-lock.json", `{"lockfileVersion":1}`, 0, 1},
		{"poetry.lock", "", 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, i := dependencies(tc.name, []byte(tc.body))
			if len(d) != tc.deps || len(i) != tc.issues {
				t.Fatalf("%v %v", d, i)
			}
		})
	}
}
func TestHiddenPromptAndEmptyManifest(t *testing.T) {
	a := &App{}
	scan, err := a.scan(context.Background(), bundle(t, map[string]string{"SKILL.md": "Hello\u202eworld"}))
	if err != nil || scan.Score == 100 || len(scan.Findings) == 0 {
		t.Fatalf("%+v %v", scan, err)
	}
	if _, err := inspect(bundle(t, map[string]string{"SKILL.md": ""})); err == nil {
		t.Fatal("empty manifest accepted")
	}
}
func TestCSRF(t *testing.T) {
	a := &App{publicURL: "https://registry.example"}
	h := a.secure(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	for _, tc := range []struct {
		origin, header string
		cookie         bool
		status         int
	}{
		{"https://evil.example", "1", true, 403}, {"https://registry.example", "", true, 403}, {"https://registry.example", "1", true, 204}, {"", "", false, 204},
	} {
		r := httptest.NewRequest("POST", "/v1/namespaces", nil)
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("X-Registry-CSRF", tc.header)
		if tc.cookie {
			r.AddCookie(&http.Cookie{Name: "registry_session", Value: "test"})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%+v got %d", tc, w.Code)
		}
	}
}
func TestLocalModeCannotUseDevToken(t *testing.T) {
	a := &App{mode: "local", devToken: "accidentally-configured-token"}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer accidentally-configured-token")
	w := httptest.NewRecorder()
	a.auth(func(w http.ResponseWriter, r *http.Request, u actor) { t.Fatal("authenticated") })(w, r)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
}
func TestUI(t *testing.T) {
	a := &App{publicURL: "http://localhost:8080", mode: "local", registration: true}
	h := a.Handler()
	for _, p := range []string{"/", "/app.js", "/style.css", "/auth/config"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", p, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d", p, w.Code)
		}
		if strings.Contains(w.Header().Get("Content-Security-Policy"), "unsafe-inline") {
			t.Fatal("unsafe CSP")
		}
	}
}
