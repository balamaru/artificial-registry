package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type accountClient struct {
	t      *testing.T
	app    *App
	cookie *http.Cookie
	token  string
}

func (c accountClient) request(method, path string, body any, status int) *httptest.ResponseRecorder {
	c.t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.RemoteAddr = "account-test:1234"
	r.Header.Set("X-Registry-CSRF", "1")
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	if c.token != "" {
		r.Header.Set("Authorization", "Bearer "+c.token)
	}
	w := httptest.NewRecorder()
	c.app.Handler().ServeHTTP(w, r)
	if w.Code != status {
		c.t.Fatalf("%s %s: got %d want %d: %s", method, path, w.Code, status, w.Body.String())
	}
	return w
}
func decodeAccount(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func (c accountClient) provision(name string) (accountClient, string) {
	c.t.Helper()
	role := "user"
	if name == "owner" {
		role = "super-admin"
	}
	w, subject := provisionFixture(c.t, c.app, name, "original-password", role)
	return accountClient{t: c.t, app: c.app, cookie: w.Result().Cookies()[0]}, subject
}
func tokenRequest(name, ns, role, parent string) map[string]any {
	grants := []grant{}
	if ns != "" {
		grants = append(grants, grant{ns, []string{role}})
	}
	return map[string]any{"name": name, "grants": grants, "expires_in_days": 30, "parent_id": parent}
}
func (c accountClient) mint(v map[string]any) (accountClient, map[string]any) {
	c.t.Helper()
	result := decodeAccount(c.t, c.request("POST", "/auth/tokens", v, 201))
	return accountClient{t: c.t, app: c.app, token: result["token"].(string)}, result
}
func TestPersonalTokenDelegation(t *testing.T) {
	a := testApp(t)
	anon := accountClient{t: t, app: a}
	admin, adminID := anon.provision("owner")
	admin.request("POST", "/v1/namespaces", map[string]string{"name": "alpha"}, 201)
	admin.request("POST", "/v1/namespaces", map[string]string{"name": "beta"}, 201)
	root, rootInfo := admin.mint(tokenRequest("root", "alpha", "admin", ""))
	child, childInfo := root.mint(tokenRequest("reader", "alpha", "read-only", ""))
	if childInfo["parent_id"] != rootInfo["id"] {
		t.Fatal("missing parent")
	}
	expiry, _ := time.Parse(time.RFC3339Nano, childInfo["expires_at"].(string))
	rootExpiry, _ := time.Parse(time.RFC3339Nano, rootInfo["expires_at"].(string))
	if expiry.After(rootExpiry) {
		t.Fatal("child outlives parent")
	}
	child.request("GET", "/v1/namespaces/alpha/skills", nil, 200)
	child.request("GET", "/v1/namespaces/beta/skills", nil, 403)
	child.request("GET", "/v1/namespaces/alpha/members", nil, 403)
	root.request("GET", "/v1/admin/users", nil, 403)
	child.request("POST", "/v1/namespaces", map[string]string{"name": "forbidden"}, 403)
	for _, v := range []map[string]any{tokenRequest("escalate", "alpha", "admin", ""), tokenRequest("other", "beta", "read-only", ""), tokenRequest("wildcard", "*", "read-only", "")} {
		child.request("POST", "/auth/tokens", v, 403)
	}
	child.request("POST", "/auth/tokens", tokenRequest("wrong-parent", "alpha", "read-only", rootInfo["id"].(string)), 403)
	escalated := tokenRequest("sys", "", "", "")
	escalated["system_roles"] = []string{"super-admin"}
	child.request("POST", "/auth/tokens", escalated, 403)
	_, grandchild := child.mint(tokenRequest("grandchild", "alpha", "read-only", ""))
	sibling, siblingInfo := admin.mint(tokenRequest("sibling", "beta", "read-only", ""))
	child.request("DELETE", "/auth/tokens/"+siblingInfo["id"].(string), nil, 404)
	listed := child.request("GET", "/auth/tokens", nil, 200).Body.String()
	if strings.Contains(listed, rootInfo["id"].(string)) { // parent_id is allowed; the root's name/prefix must not leak.
		if strings.Contains(listed, `"name":"root"`) {
			t.Fatal("listed ancestor")
		}
	}
	if strings.Contains(listed, "sibling") || strings.Contains(listed, child.token) || strings.Contains(listed, `"hash"`) {
		t.Fatal("secret or sibling disclosure")
	}
	visible := child.request("GET", "/v1/namespaces", nil, 200).Body.String()
	if strings.Contains(visible, "beta") || strings.Contains(visible, "members") {
		t.Fatal("namespace permission leakage")
	}
	child.request("POST", "/auth/password", map[string]string{"current_password": "original-password", "new_password": "different-password"}, 403)
	// Owner's current permissions constrain a token minted while owner was super-admin.
	_, err := a.db.Exec(context.Background(), "UPDATE principals SET system_role='user' WHERE subject=$1", adminID)
	if err != nil {
		t.Fatal(err)
	}
	child.request("GET", "/v1/namespaces/alpha/skills", nil, 200) // creator still has namespace admin binding
	_, err = a.db.Exec(context.Background(), "DELETE FROM role_bindings WHERE subject=$1 AND scope='alpha'", adminID)
	if err != nil {
		t.Fatal(err)
	}
	child.request("GET", "/v1/namespaces/alpha/skills", nil, 403)
	_, err = a.db.Exec(context.Background(), "UPDATE principals SET system_role='super-admin' WHERE subject=$1", adminID)
	if err != nil {
		t.Fatal(err)
	}
	root.request("DELETE", "/auth/tokens/"+rootInfo["id"].(string), nil, 204)
	child.request("GET", "/auth/me", nil, 401)
	accountClient{t: t, app: a, token: grandchild["token"].(string)}.request("GET", "/auth/me", nil, 401)
	sibling.request("GET", "/auth/me", nil, 200)
	admin.request("POST", "/auth/tokens", tokenRequest("revoked-parent", "alpha", "read-only", rootInfo["id"].(string)), 404)
	// Independent expiry checks validate ancestors, even if a corrupt child has a longer lifetime.
	_, err = a.db.Exec(context.Background(), "UPDATE personal_tokens SET expires_at=now()-interval '1 second' WHERE id=$1", siblingInfo["id"])
	if err != nil {
		t.Fatal(err)
	}
	sibling.request("GET", "/auth/me", nil, 401)
	// Full registry administration must be explicitly requested.
	sys := tokenRequest("admin", "", "", "")
	sys["system_roles"] = []string{"super-admin"}
	super, _ := admin.mint(sys)
	super.request("GET", "/v1/admin/users", nil, 200)
	super.request("GET", "/v1/namespaces/alpha/skills", nil, 403)
	var count int
	if err = a.db.QueryRow(context.Background(), "SELECT count(*) FROM audit WHERE detail::text LIKE '%'||$1||'%' OR detail::text LIKE '%'||$2||'%'", root.token, child.token).Scan(&count); err != nil || count != 0 {
		t.Fatal("secret leaked in audit", err)
	}
}
func TestDeleteUserAndPassword(t *testing.T) {
	a := testApp(t)
	anon := accountClient{t: t, app: a}
	admin, adminID := anon.provision("owner")
	deleter, deleterID := anon.provision("operator")
	ordinary, ordinaryID := anon.provision("normal")
	admin.request("PATCH", "/v1/admin/users/"+deleterID, map[string]any{"system_role": "user-delete"}, 204)
	admin.request("POST", "/v1/namespaces", map[string]string{"name": "alpha"}, 201)
	admin.request("PUT", "/v1/admin/users/"+ordinaryID+"/grants", map[string]any{"grants": []grant{{"alpha", []string{"admin"}}}}, 204)
	ordinary.request("DELETE", "/v1/admin/users/"+deleterID, nil, 403)
	token, tokenInfo := ordinary.mint(tokenRequest("own", "alpha", "read-only", ""))
	ordinary.request("POST", "/auth/password", map[string]string{"current_password": "wrong", "new_password": "replacement-password"}, 403)
	token.request("GET", "/auth/me", nil, 200)
	ordinary.request("POST", "/auth/password", map[string]string{"current_password": "original-password", "new_password": "replacement-password"}, 204)
	ordinary.request("GET", "/auth/me", nil, 401)
	token.request("GET", "/auth/me", nil, 401)
	login := anon.request("POST", "/auth/login", map[string]string{"login": "normal", "password": "replacement-password"}, 200)
	ordinary.cookie = login.Result().Cookies()[0]
	anon.request("POST", "/auth/login", map[string]string{"login": "normal", "password": "original-password"}, 401)
	token, _ = ordinary.mint(tokenRequest("after-change", "alpha", "read-only", ""))
	deleter.request("DELETE", "/v1/admin/users/"+adminID, nil, 403)
	deleter.request("DELETE", "/v1/admin/users/"+deleterID, nil, 409)
	deleter.request("POST", "/v1/admin/users", map[string]string{"email": "no@example.test", "username": "no", "password": "original-password"}, 403)
	scoped := tokenRequest("delete-users", "", "", "")
	scoped["system_roles"] = []string{"user-delete"}
	deleteToken, _ := deleter.mint(scoped)
	deleteToken.request("GET", "/v1/admin/users", nil, 200)
	deleteToken.request("DELETE", "/v1/admin/users/"+ordinaryID, nil, 204)
	token.request("GET", "/auth/me", nil, 401)
	ordinary.request("GET", "/auth/me", nil, 401)
	admin.request("PATCH", "/v1/admin/users/"+ordinaryID, map[string]bool{"disabled": false}, 404)
	admin.request("PUT", "/v1/namespaces/alpha/members/"+ordinaryID, map[string]string{"role": "read-only"}, 404)
	if strings.Contains(admin.request("GET", "/v1/admin/users", nil, 200).Body.String(), ordinaryID) {
		t.Fatal("deleted user listed")
	}
	if strings.Contains(admin.request("GET", "/v1/namespaces/alpha/member-candidates", nil, 200).Body.String(), ordinaryID) {
		t.Fatal("deleted candidate listed")
	}
	var deleted, revoked bool
	if err := a.db.QueryRow(context.Background(), "SELECT disabled AND deleted_at IS NOT NULL FROM principals WHERE subject=$1", ordinaryID).Scan(&deleted); err != nil || !deleted {
		t.Fatal("missing tombstone", err)
	}
	if err := a.db.QueryRow(context.Background(), "SELECT revoked_at IS NOT NULL FROM personal_tokens WHERE id=$1", tokenInfo["id"]).Scan(&revoked); err != nil || !revoked {
		t.Fatal("token not revoked", err)
	}
	// OIDC-style provisioning cannot recreate the retained identity.
	r := httptest.NewRequest("GET", "/auth/me", nil)
	w := httptest.NewRecorder()
	a.serveActor(w, r, ordinaryID, a.me, true)
	if w.Code != 401 {
		t.Fatalf("deleted identity resurrected: %d", w.Code)
	}
	admin.request("DELETE", "/v1/admin/users/"+adminID, nil, 409)
	admin.request("DELETE", "/v1/admin/users/"+deleterID, nil, 204)
	deleteToken.request("GET", "/auth/me", nil, 401)
}
func TestTokenOwnershipResetAndDepth(t *testing.T) {
	a := testApp(t)
	anon := accountClient{t: t, app: a}
	admin, _ := anon.provision("owner")
	other, otherID := anon.provision("other")
	admin.request("POST", "/v1/namespaces", map[string]string{"name": "alpha"}, 201)
	root, info := admin.mint(tokenRequest("root", "*", "admin", ""))
	other.request("POST", "/auth/tokens", tokenRequest("stolen", "alpha", "read-only", info["id"].(string)), 404)
	other.request("DELETE", "/auth/tokens/"+info["id"].(string), nil, 404)
	leaf := root
	for i := 0; i < 8; i++ {
		leaf, _ = leaf.mint(tokenRequest("child", "alpha", "read-only", ""))
	}
	leaf.request("POST", "/auth/tokens", tokenRequest("too-deep", "alpha", "read-only", ""), 400)
	_, err := a.db.Exec(context.Background(), "UPDATE personal_tokens SET expires_at=now()-interval '1 second' WHERE id=$1", info["id"])
	if err != nil {
		t.Fatal(err)
	}
	leaf.request("GET", "/auth/me", nil, 401)
	admin.request("PUT", "/v1/admin/users/"+otherID+"/grants", map[string]any{"grants": []grant{{"alpha", []string{"read-only"}}}}, 204)
	token, _ := other.mint(tokenRequest("other", "alpha", "read-only", ""))
	admin.request("PATCH", "/v1/admin/users/"+otherID, map[string]string{"password": "reset-password-long"}, 204)
	token.request("GET", "/auth/me", nil, 401)
}
