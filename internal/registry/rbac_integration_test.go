package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func isolatedDatabase(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "rbac_" + randomToken()[:16]
	if _, err = pool.Exec(context.Background(), "CREATE SCHEMA "+schema); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); pool.Close() })
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}
func testApp(t *testing.T) *App {
	t.Helper()
	t.Setenv("DATABASE_URL", isolatedDatabase(t))
	t.Setenv("AUTH_MODE", "local")
	t.Setenv("PUBLIC_URL", "http://localhost:8080")
	t.Setenv("SCAN_OSV", "false")
	t.Setenv("REGISTRATION_ENABLED", "true")
	a, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}
func TestScopedRolesAndAdministration(t *testing.T) {
	a := testApp(t)
	h := a.Handler()
	request := func(method, path string, body []byte, cookie *http.Cookie, status int, hash string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.RemoteAddr = "test:40000"
		r.Header.Set("X-Registry-CSRF", "1")
		r.Header.Set("Content-Type", "application/json")
		if (method == "POST" || method == "PUT") && strings.Contains(path, "/versions/") && version.MatchString(path[strings.LastIndex(path, "/")+1:]) {
			r.Header.Set("Content-Type", "application/zip")
		}
		if hash != "" {
			r.Header.Set("If-Match", hash)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s %s: got %d want %d: %s", method, path, w.Code, status, w.Body.String())
		}
		return w
	}
	reg := request("POST", "/auth/register", []byte(`{"email":"owner@example.test","username":"owner","password":"a-long-password"}`), nil, 201, "")
	admin := reg.Result().Cookies()[0]
	var first map[string]string
	json.Unmarshal(reg.Body.Bytes(), &first)
	me := request("GET", "/auth/me", nil, admin, 200, "")
	if !strings.Contains(me.Body.String(), `"system_role":"super-admin"`) {
		t.Fatal("first user was not promoted")
	}
	otherReg := request("POST", "/auth/register", []byte(`{"email":"attacker@example.test","username":"attacker","password":"a-long-password","system_role":"super-admin","grants":[{"namespace":"*","roles":["admin"]}]}`), nil, 201, "")
	attacker := otherReg.Result().Cookies()[0]
	profile := request("GET", "/auth/me", nil, attacker, 200, "")
	if strings.Contains(profile.Body.String(), `"system_role":"super-admin"`) {
		t.Fatal("registration escalated privileges")
	}
	request("GET", "/v1/admin/users", nil, attacker, 403, "")
	request("POST", "/v1/namespaces", []byte(`{"name":"forbidden"}`), attacker, 403, "")
	for _, ns := range []string{"allowed", "private"} {
		request("POST", "/v1/namespaces", []byte(`{"name":"`+ns+`"}`), admin, 201, "")
	}
	create := request("POST", "/v1/admin/users", []byte(`{"email":"member@example.test","username":"member","password":"a-long-password"}`), admin, 201, "")
	if len(create.Result().Cookies()) != 0 {
		t.Fatal("creating user replaced admin session")
	}
	var member map[string]string
	json.Unmarshal(create.Body.Bytes(), &member)
	sub := member["subject"]
	login := request("POST", "/auth/login", []byte(`{"login":"member","password":"a-long-password"}`), nil, 200, "")
	user := login.Result().Cookies()[0]
	setGrants := func(scope string, roles ...string) {
		t.Helper()
		b, _ := json.Marshal(map[string]any{"grants": []grant{{scope, roles}}})
		request("PUT", "/v1/admin/users/"+sub+"/grants", b, admin, 204, "")
	}
	setGrants("allowed", "write-only")
	path := "/v1/namespaces/allowed/skills/example/versions/1.0.0"
	zip := bundle(t, map[string]string{"SKILL.md": "# Safe skill"})
	replacement := bundle(t, map[string]string{"SKILL.md": "# Updated skill"})
	uploaded := request("POST", path, zip, user, 201, "")
	var result struct {
		SHA string `json:"sha256"`
	}
	json.Unmarshal(uploaded.Body.Bytes(), &result)
	originalHash := result.SHA
	request("GET", "/v1/namespaces/allowed/skills", nil, user, 403, "")
	request("GET", path, nil, user, 403, "")
	request("POST", path+"/approve", nil, user, 403, "")
	request("POST", "/v1/namespaces/private/skills/example/versions/1.0.0", zip, user, 403, "")
	request("PUT", "/v1/admin/users/"+sub+"/grants", []byte(`{"grants":[]}`), user, 403, "")
	request("POST", path+"/approve", nil, admin, 204, "")
	setGrants("allowed", "read-only")
	request("GET", path, nil, user, 200, "")
	request("POST", path, zip, user, 403, "")
	request("PUT", path, replacement, user, 403, originalHash)
	request("DELETE", path, nil, user, 403, originalHash)
	request("POST", "/v1/namespaces/allowed/usage", []byte(`{}`), user, 403, "")
	setGrants("allowed", "read-only", "write-only")
	request("GET", path, nil, user, 200, "")
	request("POST", "/v1/namespaces/allowed/skills/example/versions/2.0.0", zip, user, 201, "")
	request("PUT", path, replacement, user, 403, originalHash)
	setGrants("allowed", "read-write")
	request("PUT", path, replacement, user, 428, "")
	request("PUT", path, replacement, user, 412, "outdated")
	updated := request("PUT", path, replacement, user, 200, originalHash)
	json.Unmarshal(updated.Body.Bytes(), &result)
	newHash := result.SHA
	if newHash == originalHash || !strings.Contains(updated.Body.String(), `"revision":2`) {
		t.Fatal("update did not replace bundle")
	}
	request("GET", path, nil, user, 404, "")
	request("POST", path+"/approve", nil, user, 403, "")
	request("DELETE", path, nil, user, 403, newHash)
	request("POST", path+"/approve", nil, admin, 204, "")
	downloaded := request("GET", path, nil, user, 200, "")
	if !bytes.Equal(downloaded.Body.Bytes(), replacement) {
		t.Fatal("old bundle returned after update")
	}
	setGrants("allowed", "update")
	request("GET", path, nil, user, 403, "")
	request("GET", "/v1/namespaces/allowed/skills", nil, user, 200, "")
	request("PUT", path, zip, user, 200, newHash)
	setGrants("allowed", "reviewer")
	request("POST", path+"/approve", nil, user, 204, "")
	request("POST", "/v1/namespaces/allowed/skills/no/versions/1.0.0", zip, user, 403, "")
	setGrants("allowed", "auditor")
	request("GET", "/v1/namespaces/allowed/audit", nil, user, 200, "")
	request("GET", "/v1/namespaces/allowed/usage", nil, user, 200, "")
	request("GET", path, nil, user, 403, "")
	setGrants("allowed", "delete")
	request("DELETE", path, nil, user, 412, newHash)
	request("DELETE", path, nil, user, 204, originalHash)
	request("GET", path, nil, admin, 404, "")
	request("DELETE", "/v1/namespaces/allowed/skills/example", nil, user, 204, "")
	request("DELETE", "/v1/namespaces/allowed/skills/example", nil, user, 404, "")
	setGrants("allowed", "maintainer")
	request("GET", "/v1/namespaces/allowed/members", nil, user, 403, "")
	request("GET", "/v1/namespaces/allowed/audit", nil, user, 200, "")
	setGrants("allowed", "admin")
	request("GET", "/v1/namespaces/allowed/members", nil, user, 200, "")
	request("GET", "/v1/admin/users", nil, user, 403, "")
	request("POST", "/v1/namespaces", []byte(`{"name":"not-allowed"}`), user, 403, "")
	request("PUT", "/v1/namespaces/allowed/members/attacker", []byte(`{"roles":["read-only","update"]}`), user, 204, "")
	request("GET", "/v1/namespaces/allowed/skills", nil, attacker, 200, "")
	request("GET", "/v1/namespaces/private/skills", nil, attacker, 403, "")
	setGrants("*", "read-only")
	request("POST", "/v1/namespaces", []byte(`{"name":"future"}`), admin, 201, "")
	ns := request("GET", "/v1/namespaces", nil, user, 200, "")
	if !strings.Contains(ns.Body.String(), "future") || !strings.Contains(ns.Body.String(), "private") {
		t.Fatal("wildcard missed namespaces")
	}
	request("GET", "/v1/namespaces/future/skills", nil, user, 200, "")
	request("POST", "/v1/namespaces/future/skills/new/versions/1.0.0", zip, user, 403, "")
	setGrants("*", "admin")
	request("POST", "/v1/namespaces", []byte(`{"name":"global-created"}`), user, 201, "")
	request("GET", "/v1/admin/users", nil, user, 403, "")
	request("PUT", "/v1/admin/users/"+sub+"/grants", []byte(`{"grants":[{"namespace":"missing","roles":["read-only"]}]}`), admin, 400, "")
	// Invalid replacements roll back and retain the previous grants.
	request("GET", "/v1/namespaces/private/members", nil, user, 200, "")
	request("PATCH", "/v1/admin/users/"+sub, []byte(`{"disabled":true}`), admin, 204, "")
	request("GET", "/auth/me", nil, user, 401, "")
	request("POST", "/auth/login", []byte(`{"login":"member","password":"a-long-password"}`), nil, 401, "")
	request("PATCH", "/v1/admin/users/"+sub, []byte(`{"disabled":false,"password":"new-long-password"}`), admin, 204, "")
	request("GET", "/auth/me", nil, user, 401, "")
	request("POST", "/auth/login", []byte(`{"login":"member","password":"a-long-password"}`), nil, 401, "")
	request("POST", "/auth/login", []byte(`{"login":"member","password":"new-long-password"}`), nil, 200, "")
	request("PATCH", "/v1/admin/users/"+first["subject"], []byte(`{"disabled":true}`), admin, 409, "")
	request("PATCH", "/v1/admin/users/"+first["subject"], []byte(`{"system_role":"user"}`), admin, 409, "")
	audit := request("GET", "/v1/admin/audit", nil, admin, 200, "")
	if strings.Contains(audit.Body.String(), "new-long-password") || strings.Contains(audit.Body.String(), "a-long-password") {
		t.Fatal("password in audit")
	}
	a.registration = false
	request("POST", "/auth/register", []byte(`{}`), nil, 403, "")
	request("POST", "/v1/admin/users", []byte(`{"email":"closed@example.test","username":"closed","password":"a-long-password"}`), admin, 201, "")
}
func TestConcurrentFirstUser(t *testing.T) {
	a := testApp(t)
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := httptest.NewRequest("POST", "/auth/register", strings.NewReader(fmt.Sprintf(`{"email":"user%d@example.test","username":"user%d","password":"a-long-password"}`, i, i)))
			w := httptest.NewRecorder()
			a.Handler().ServeHTTP(w, r)
			statuses <- w.Code
		}(i)
	}
	wg.Wait()
	close(statuses)
	for s := range statuses {
		if s != 201 {
			t.Fatalf("registration status %d", s)
		}
	}
	var n int
	if err := a.db.QueryRow(context.Background(), "SELECT count(*) FROM principals WHERE system_role='super-admin'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("bootstrap admins=%d err=%v", n, err)
	}
}
func TestLegacyMigrationKeepsRevocations(t *testing.T) {
	dsn := isolatedDatabase(t)
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, statement := range strings.Split(schema+authSchema, ";") {
		if strings.TrimSpace(statement) != "" {
			if _, err = db.Exec(ctx, statement); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, statement := range []string{
		"INSERT INTO users(subject,email,username,password_hash,created_at) VALUES('first','first@example.test','first','hash',now()-interval '1 day'),('second','second@example.test','second','hash',now())",
		"INSERT INTO namespaces(name) VALUES('legacy')",
		"INSERT INTO memberships(namespace,subject,role) VALUES('legacy','first','admin'),('legacy','second','reader')",
	} {
		if _, err = db.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("DATABASE_URL", dsn)
	t.Setenv("AUTH_MODE", "local")
	t.Setenv("PUBLIC_URL", "http://localhost:8080")
	a, err := New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !a.systemAdmin(ctx, actor{"first"}) || a.systemAdmin(ctx, actor{"second"}) {
		t.Fatal("incorrect migrated owner")
	}
	var roles []string
	if err = a.db.QueryRow(ctx, "SELECT array_agg(role) FROM role_bindings WHERE subject='second'").Scan(&roles); err != nil || !has(roles, "reader") {
		t.Fatal("legacy role lost")
	}
	_, err = a.db.Exec(ctx, "DELETE FROM role_bindings WHERE subject='second'")
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	a, err = New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	var n int
	a.db.QueryRow(ctx, "SELECT count(*) FROM role_bindings WHERE subject='second'").Scan(&n)
	if n != 0 {
		t.Fatal("restart resurrected revoked legacy membership")
	}
}

func TestLegacyOIDCChoosesNamespaceAdmin(t *testing.T) {
	dsn := isolatedDatabase(t)
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, statement := range strings.Split(schema+authSchema, ";") {
		if strings.TrimSpace(statement) != "" {
			if _, err = db.Exec(ctx, statement); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, statement := range []string{
		"INSERT INTO namespaces(name,created_at) VALUES('old',now()-interval '1 day'),('recent',now())",
		"INSERT INTO memberships(namespace,subject,role) VALUES('old','a-reader','reader'),('old','z-admin','admin'),('recent','b-admin','admin')",
	} {
		if _, err = db.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("DATABASE_URL", dsn)
	t.Setenv("AUTH_MODE", "local")
	t.Setenv("PUBLIC_URL", "http://localhost:8080")
	a, err := New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if !a.systemAdmin(ctx, actor{"z-admin"}) || a.systemAdmin(ctx, actor{"a-reader"}) || a.systemAdmin(ctx, actor{"b-admin"}) {
		t.Fatal("legacy bootstrap promoted the wrong identity")
	}
}
