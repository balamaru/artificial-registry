package registry

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strconv"
)

//go:embed web/*
var web embed.FS

func (a *App) routes(m *http.ServeMux) {
	m.HandleFunc("GET /auth/config", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{"local": a.mode != "oidc", "registration": a.registration && a.mode != "oidc", "oidc": a.oauth != nil})
	})
	m.HandleFunc("POST /auth/register", a.register)
	m.HandleFunc("POST /auth/login", a.login)
	m.HandleFunc("POST /auth/logout", a.auth(a.logout))
	m.HandleFunc("GET /auth/me", a.auth(a.me))
	m.HandleFunc("GET /auth/oidc/login", a.oidcLogin)
	m.HandleFunc("GET /auth/oidc/callback", a.oidcCallback)
	m.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if a.db.Ping(r.Context()) != nil {
			problem(w, 503, "database unavailable")
			return
		}
		w.WriteHeader(204)
	})
	m.HandleFunc("GET /v1/namespaces", a.auth(a.namespaces))
	m.HandleFunc("GET /v1/namespaces/{ns}/members", a.auth(a.members))
	m.HandleFunc("DELETE /v1/namespaces/{ns}/members/{sub}", a.auth(a.removeMember))
	m.HandleFunc("POST /v1/namespaces/{ns}/skills/{skill}/versions/{version}/reject", a.auth(a.reject))
	m.HandleFunc("POST /v1/namespaces/{ns}/skills/{skill}/versions/{version}/rescan", a.auth(a.rescan))
	m.HandleFunc("GET /v1/roles", a.auth(a.roleCatalog))
	m.HandleFunc("GET /v1/admin/users", a.auth(a.listUsers))
	m.HandleFunc("POST /v1/admin/users", a.auth(a.createUser))
	m.HandleFunc("PATCH /v1/admin/users/{sub}", a.auth(a.updateUser))
	m.HandleFunc("PUT /v1/admin/users/{sub}/grants", a.auth(a.userGrants))
	m.HandleFunc("GET /v1/admin/audit", a.auth(func(w http.ResponseWriter, r *http.Request, u actor) { r.SetPathValue("ns", "*"); a.audit(w, r, u) }))
	m.HandleFunc("PUT /v1/namespaces/{ns}/skills/{skill}/versions/{version}", a.auth(a.updateSkill))
	m.HandleFunc("DELETE /v1/namespaces/{ns}/skills/{skill}/versions/{version}", a.auth(a.deleteSkill))
	m.HandleFunc("DELETE /v1/namespaces/{ns}/skills/{skill}", a.auth(a.deleteSkill))
	files, _ := fs.Sub(web, "web")
	m.Handle("GET /", http.FileServer(http.FS(files)))
}
func pageLimit(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n < 1 || n > 100 {
		n = 50
	}
	return n
}
func pageOffset(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if n < 0 || n > 1000000 {
		n = 0
	}
	return n
}
func (a *App) removeMember(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.allowed(r, u, "members") {
		problem(w, 403, "forbidden")
		return
	}
	if r.PathValue("sub") == u.Subject {
		problem(w, 409, "cannot remove yourself")
		return
	}
	_, err := a.db.Exec(r.Context(), "DELETE FROM role_bindings WHERE scope=$1 AND subject=$2", r.PathValue("ns"), r.PathValue("sub"))
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	a.log(r.Context(), u, "member.remove", r.PathValue("ns"), "", map[string]string{"subject": r.PathValue("sub")})
	w.WriteHeader(204)
}
func (a *App) reject(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.allowed(r, u, "review") {
		problem(w, 403, "forbidden")
		return
	}
	var v struct{ Reason string }
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&v) != nil || len(v.Reason) < 3 || len(v.Reason) > 1000 {
		problem(w, 400, "reason of 3–1000 bytes required")
		return
	}
	tag, err := a.db.Exec(r.Context(), "UPDATE skills SET status='rejected' WHERE namespace=$1 AND name=$2 AND version=$3 AND status IN ('quarantined','published')", r.PathValue("ns"), r.PathValue("skill"), r.PathValue("version"))
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 409, "version not found or already rejected")
		return
	}
	a.log(r.Context(), u, "skill.reject", r.PathValue("ns"), r.PathValue("skill"), map[string]string{"version": r.PathValue("version"), "reason": v.Reason})
	w.WriteHeader(204)
}
func (a *App) rescan(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.allowed(r, u, "review") {
		problem(w, 403, "forbidden")
		return
	}
	// Hold the row lock so approval cannot race a rescan of a published bundle.
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer tx.Rollback(r.Context())
	var data []byte
	if tx.QueryRow(r.Context(), "SELECT bundle FROM skills WHERE namespace=$1 AND name=$2 AND version=$3 FOR UPDATE", r.PathValue("ns"), r.PathValue("skill"), r.PathValue("version")).Scan(&data) != nil {
		problem(w, 404, "version not found")
		return
	}
	scan, err := a.scan(r.Context(), data)
	if err != nil {
		problem(w, 400, err.Error())
		return
	}
	b, _ := json.Marshal(scan)
	_, err = tx.Exec(r.Context(), "UPDATE skills SET scan=$4,status='quarantined' WHERE namespace=$1 AND name=$2 AND version=$3", r.PathValue("ns"), r.PathValue("skill"), r.PathValue("version"), b)
	if err != nil || tx.Commit(r.Context()) != nil {
		problem(w, 500, "database error")
		return
	}
	a.log(r.Context(), u, "skill.rescan", r.PathValue("ns"), r.PathValue("skill"), map[string]string{"version": r.PathValue("version")})
	respond(w, 200, scan)
}
