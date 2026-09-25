package registry

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

const rbacSchema = `
CREATE TABLE IF NOT EXISTS principals (subject text PRIMARY KEY, system_role text NOT NULL DEFAULT 'user' CHECK(system_role IN ('user','super-admin')), disabled boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS registry_settings (key text PRIMARY KEY, value text NOT NULL);
CREATE TABLE IF NOT EXISTS role_bindings (subject text NOT NULL REFERENCES principals(subject), scope text NOT NULL, role text NOT NULL CHECK(role IN ('reader','publisher','read-only','write-only','read-write','update','delete','reviewer','auditor','maintainer','admin')), PRIMARY KEY(subject,scope,role));
CREATE INDEX IF NOT EXISTS bindings_scope ON role_bindings(scope,subject);
INSERT INTO principals(subject,created_at) SELECT subject,created_at FROM users ON CONFLICT DO NOTHING;
INSERT INTO principals(subject) SELECT DISTINCT subject FROM memberships ON CONFLICT DO NOTHING;
INSERT INTO role_bindings(subject,scope,role) SELECT subject,namespace,role FROM memberships WHERE NOT EXISTS(SELECT 1 FROM registry_settings WHERE key='rbac-v1') ON CONFLICT DO NOTHING;
INSERT INTO registry_settings(key,value) VALUES('rbac-v1','done') ON CONFLICT DO NOTHING;
INSERT INTO registry_settings(key,value) SELECT 'bootstrap-admin', subject FROM (SELECT subject,0 AS priority,created_at FROM users UNION ALL SELECT m.subject,1,n.created_at FROM memberships m JOIN namespaces n ON n.name=m.namespace WHERE m.role='admin') candidates ORDER BY priority,created_at,subject LIMIT 1 ON CONFLICT DO NOTHING;
UPDATE principals SET system_role='super-admin' WHERE subject=(SELECT value FROM registry_settings WHERE key='bootstrap-admin') AND NOT EXISTS(SELECT 1 FROM registry_settings WHERE key='bootstrap-migrated');
INSERT INTO registry_settings(key,value) SELECT 'bootstrap-migrated','done' WHERE EXISTS(SELECT 1 FROM registry_settings WHERE key='bootstrap-admin') ON CONFLICT DO NOTHING;
ALTER TABLE skills ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE skills ADD COLUMN IF NOT EXISTS revision integer NOT NULL DEFAULT 1;
`

var rolePermissions = map[string][]string{
	"read-only":  {"list", "read"},
	"write-only": {"write"},
	"read-write": {"list", "read", "write", "update", "usage-write"},
	"update":     {"list", "update"},
	"delete":     {"list", "delete"},
	"reviewer":   {"list", "read", "review"},
	"auditor":    {"list", "audit", "usage-read"},
	"maintainer": {"list", "read", "write", "update", "delete", "review", "audit", "usage-read", "usage-write"},
	"admin":      {"list", "read", "write", "update", "delete", "review", "audit", "usage-read", "usage-write", "members"},
	// Preserve existing clients while exposing more precise roles in the UI.
	"reader":    {"list", "read", "usage-write"},
	"publisher": {"list", "read", "write", "usage-write"},
}

func permissionsFor(roles []string) []string {
	found := map[string]bool{}
	for _, role := range roles {
		for _, permission := range rolePermissions[role] {
			found[permission] = true
		}
	}
	out := []string{}
	for p := range found {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
func has(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func validRoles(roles []string) bool {
	if len(roles) == 0 || len(roles) > len(rolePermissions) {
		return false
	}
	for _, r := range roles {
		if _, ok := rolePermissions[r]; !ok {
			return false
		}
	}
	return true
}
func (a *App) systemAdmin(ctx context.Context, u actor) bool {
	var yes bool
	_ = a.db.QueryRow(ctx, "SELECT system_role='super-admin' AND NOT disabled FROM principals WHERE subject=$1", u.Subject).Scan(&yes)
	return yes
}
func (a *App) allowed(r *http.Request, u actor, permission string) bool {
	if !validPath(r) {
		return false
	}
	if a.systemAdmin(r.Context(), u) {
		return true
	}
	var roles []string
	err := a.db.QueryRow(r.Context(), "SELECT COALESCE(array_agg(b.role),'{}') FROM role_bindings b JOIN principals p ON p.subject=b.subject WHERE b.subject=$1 AND b.scope IN ('*',$2) AND NOT p.disabled", u.Subject, r.PathValue("ns")).Scan(&roles)
	return err == nil && has(permissionsFor(roles), permission)
}
func (a *App) canCreateNamespace(ctx context.Context, u actor) bool {
	if a.systemAdmin(ctx, u) {
		return true
	}
	var yes bool
	_ = a.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM role_bindings b JOIN principals p USING(subject) WHERE subject=$1 AND scope='*' AND role='admin' AND NOT p.disabled)", u.Subject).Scan(&yes)
	return yes
}

// The same advisory lock serializes local registration and first external login.
func ensurePrincipal(ctx context.Context, tx pgx.Tx, subject string) error {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(741923106)"); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "INSERT INTO principals(subject) VALUES($1) ON CONFLICT DO NOTHING", subject); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, "INSERT INTO registry_settings(key,value) VALUES('bootstrap-admin',$1) ON CONFLICT DO NOTHING", subject)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		if _, err = tx.Exec(ctx, "UPDATE principals SET system_role='super-admin' WHERE subject=$1", subject); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "INSERT INTO registry_settings(key,value) VALUES('bootstrap-migrated','done') ON CONFLICT DO NOTHING")
	}
	return err
}
func (a *App) serveActor(w http.ResponseWriter, r *http.Request, subject string, next endpoint, external bool) {
	if external {
		var exists bool
		if err := a.db.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM principals WHERE subject=$1)", subject).Scan(&exists); err != nil {
			problem(w, 503, "authentication unavailable")
			return
		}
		if !exists {
			tx, err := a.db.Begin(r.Context())
			if err != nil {
				problem(w, 503, "authentication unavailable")
				return
			}
			defer tx.Rollback(r.Context())
			if ensurePrincipal(r.Context(), tx, subject) != nil || tx.Commit(r.Context()) != nil {
				problem(w, 503, "authentication unavailable")
				return
			}
		}
	}
	var disabled bool
	if a.db.QueryRow(r.Context(), "SELECT disabled FROM principals WHERE subject=$1", subject).Scan(&disabled) != nil || disabled {
		problem(w, 401, "account disabled or unavailable")
		return
	}
	next(w, r, actor{subject})
}
func auditTx(ctx context.Context, tx pgx.Tx, u actor, action, ns, skill string, detail any) error {
	body, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "INSERT INTO audit(subject,action,namespace,skill,detail) VALUES($1,$2,$3,$4,$5)", u.Subject, action, ns, skill, body)
	return err
}

type grant struct {
	Namespace string   `json:"namespace"`
	Roles     []string `json:"roles"`
}

func validateGrants(ctx context.Context, tx pgx.Tx, grants []grant) error {
	if len(grants) > 1000 {
		return errors.New("too many namespace grants")
	}
	seen := map[string]bool{}
	for _, g := range grants {
		if seen[g.Namespace] || !validRoles(g.Roles) {
			return errors.New("invalid or duplicate namespace grant")
		}
		seen[g.Namespace] = true
		if g.Namespace != "*" {
			var exists bool
			if !identifier.MatchString(g.Namespace) {
				return errors.New("invalid namespace")
			}
			if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM namespaces WHERE name=$1)", g.Namespace).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return errors.New("namespace not found")
			}
		}
	}
	return nil
}
func replaceGrants(ctx context.Context, tx pgx.Tx, subject string, grants []grant) error {
	if err := validateGrants(ctx, tx, grants); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "DELETE FROM role_bindings WHERE subject=$1", subject); err != nil {
		return err
	}
	for _, g := range grants {
		for _, role := range g.Roles {
			if _, err := tx.Exec(ctx, "INSERT INTO role_bindings(subject,scope,role) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", subject, g.Namespace, role); err != nil {
				return err
			}
		}
	}
	return nil
}
func (a *App) roleCatalog(w http.ResponseWriter, r *http.Request, u actor) {
	respond(w, 200, rolePermissions)
}
func (a *App) namespaces(w http.ResponseWriter, r *http.Request, u actor) {
	admin := a.systemAdmin(r.Context(), u)
	rows, err := a.db.Query(r.Context(), `SELECT n.name,COALESCE(array_agg(DISTINCT b.role) FILTER (WHERE b.role IS NOT NULL),'{}') FROM namespaces n LEFT JOIN role_bindings b ON b.subject=$1 AND b.scope IN ('*',n.name) WHERE $2 OR b.subject IS NOT NULL GROUP BY n.name ORDER BY n.name`, u.Subject, admin)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []any{}
	for rows.Next() {
		var ns string
		var roles []string
		if rows.Scan(&ns, &roles) != nil {
			problem(w, 500, "database error")
			return
		}
		if admin {
			roles = []string{"admin"}
		}
		sort.Strings(roles)
		items = append(items, map[string]any{"name": ns, "role": strings.Join(roles, ", "), "roles": roles, "permissions": permissionsFor(roles)})
	}
	if rows.Err() != nil {
		problem(w, 500, "database error")
		return
	}
	respond(w, 200, items)
}
func (a *App) members(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.allowed(r, u, "members") {
		problem(w, 403, "forbidden")
		return
	}
	rows, err := a.db.Query(r.Context(), `SELECT b.subject,array_agg(b.role ORDER BY b.role),COALESCE(u.username,'') FROM role_bindings b LEFT JOIN users u ON u.subject=b.subject WHERE scope=$1 GROUP BY b.subject,u.username ORDER BY b.subject`, r.PathValue("ns"))
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []any{}
	for rows.Next() {
		var sub, name string
		var roles []string
		if rows.Scan(&sub, &roles, &name) != nil {
			problem(w, 500, "database error")
			return
		}
		items = append(items, map[string]any{"subject": sub, "username": name, "role": strings.Join(roles, ", "), "roles": roles})
	}
	if rows.Err() != nil {
		problem(w, 500, "database error")
		return
	}
	respond(w, 200, items)
}
func (a *App) setMember(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.allowed(r, u, "members") {
		problem(w, 403, "forbidden")
		return
	}
	var v struct {
		Role  string   `json:"role"`
		Roles []string `json:"roles"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&v) != nil {
		problem(w, 400, "invalid member")
		return
	}
	if len(v.Roles) == 0 && v.Role != "" {
		v.Roles = []string{v.Role}
	}
	if !validRoles(v.Roles) {
		problem(w, 400, "invalid roles")
		return
	}
	var sub string
	err := a.db.QueryRow(r.Context(), "SELECT p.subject FROM principals p LEFT JOIN users u USING(subject) WHERE p.subject=$1 OR u.username=$1 OR u.email=$1 ORDER BY (p.subject=$1) DESC LIMIT 1", r.PathValue("sub")).Scan(&sub)
	if err != nil {
		problem(w, 404, "user not found; external users must sign in first")
		return
	}
	if sub == u.Subject && !has(v.Roles, "admin") {
		problem(w, 400, "cannot demote yourself")
		return
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), "SELECT subject FROM principals WHERE subject=$1 FOR UPDATE", sub); err == nil {
		_, err = tx.Exec(r.Context(), "DELETE FROM role_bindings WHERE subject=$1 AND scope=$2", sub, r.PathValue("ns"))
	}
	if err == nil {
		for _, role := range v.Roles {
			_, err = tx.Exec(r.Context(), "INSERT INTO role_bindings(subject,scope,role) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", sub, r.PathValue("ns"), role)
			if err != nil {
				break
			}
		}
	}
	if err != nil || auditTx(r.Context(), tx, u, "member.set", r.PathValue("ns"), "", map[string]any{"subject": sub, "roles": v.Roles}) != nil || tx.Commit(r.Context()) != nil {
		problem(w, 500, "database error")
		return
	}
	w.WriteHeader(204)
}
