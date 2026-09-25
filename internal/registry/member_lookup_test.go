package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestMemberCandidates(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	for _, subject := range []string{"aaaa", "bbb", "external-j", "jhoen", "disabled"} {
		if _, err := a.db.Exec(ctx, "INSERT INTO principals(subject,disabled) VALUES($1,$2)", subject, subject == "disabled"); err != nil {
			t.Fatal(err)
		}
		if _, err := a.db.Exec(ctx, "INSERT INTO sessions(hash,subject,expires_at) VALUES($1,$2,now()+interval '1 hour')", tokenHash("test-"+subject), subject); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []struct{ subject, username, email string }{
		{"aaaa", "aaaa", "aaaa@example.test"}, {"bbb", "bbb", "contact+lookup@example.test"},
		{"external-j", "ccc", "ccc@example.test"}, {"jhoen", "jhoen", "jhoen@example.test"},
		{"disabled", "disabled", "disabled@example.test"},
	} {
		if _, err := a.db.Exec(ctx, "INSERT INTO users(subject,username,email,password_hash) VALUES($1,$2,$3,'test-only')", v.subject, v.username, v.email); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.db.Exec(ctx, "INSERT INTO namespaces(name) VALUES('team'),('private')"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(ctx, "INSERT INTO role_bindings(subject,scope,role) VALUES('jhoen','team','admin'),('aaaa','team','read-only')"); err != nil {
		t.Fatal(err)
	}
	h := a.Handler()
	request := func(path, subject string, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		if subject != "" {
			r.AddCookie(&http.Cookie{Name: "registry_session", Value: "test-" + subject})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s as %s: %d %s", path, subject, w.Code, w.Body.String())
		}
		return w
	}
	base := "/v1/namespaces/team/member-candidates"
	for _, tc := range []struct {
		query string
		names []string
	}{
		{"", []string{"aaaa", "bbb", "ccc", "jhoen"}},
		{"JHO", []string{"jhoen"}}, {"CONTACT+", []string{"bbb"}},
		{"EXTERNAL-J", []string{"ccc"}}, {"j", []string{"ccc", "jhoen"}},
		{"nonexistent", []string{}}, {"%", []string{}}, {"_", []string{}},
	} {
		w := request(base+"?q="+url.QueryEscape(tc.query), "jhoen", 200)
		var result struct {
			Items []map[string]string `json:"items"`
			More  bool                `json:"has_more"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if len(result.Items) != len(tc.names) || result.More {
			t.Fatalf("query %q: %s", tc.query, w.Body.String())
		}
		for i, item := range result.Items {
			if item["username"] != tc.names[i] || len(item) != 3 {
				t.Fatalf("unexpected directory fields/results: %v", item)
			}
		}
	}
	first := request(base+"?limit=2", "jhoen", 200)
	if !strings.Contains(first.Body.String(), `"has_more":true`) {
		t.Fatal("missing pagination")
	}
	last := request(base+"?limit=2&offset=2", "jhoen", 200)
	if !strings.Contains(last.Body.String(), `"has_more":false`) || strings.Contains(last.Body.String(), `"username":"aaaa"`) {
		t.Fatal("invalid second page")
	}
	request(base, "", 401)
	request(base, "aaaa", 403)
	request(base, "disabled", 401)
	request("/v1/namespaces/private/member-candidates", "jhoen", 403)
	request("/v1/admin/users", "jhoen", 403)
	request(base+"?q="+strings.Repeat("x", 255), "jhoen", 400)
}
