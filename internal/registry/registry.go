package registry

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
)

const schema = `
CREATE TABLE IF NOT EXISTS namespaces (name text PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS memberships (namespace text NOT NULL REFERENCES namespaces(name), subject text NOT NULL, role text NOT NULL CHECK(role IN ('reader','publisher','admin')), PRIMARY KEY(namespace,subject));
CREATE TABLE IF NOT EXISTS skills (namespace text NOT NULL REFERENCES namespaces(name), name text NOT NULL, version text NOT NULL, sha256 text NOT NULL, bundle bytea NOT NULL, scan jsonb NOT NULL, status text NOT NULL CHECK(status IN ('quarantined','published','rejected')), uploaded_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(namespace,name,version));
CREATE TABLE IF NOT EXISTS audit (id bigserial PRIMARY KEY, at timestamptz NOT NULL DEFAULT now(), subject text NOT NULL, action text NOT NULL, namespace text NOT NULL, skill text NOT NULL DEFAULT '', detail jsonb NOT NULL DEFAULT '{}'::jsonb);
CREATE INDEX IF NOT EXISTS audit_namespace_at ON audit(namespace,at DESC);
CREATE TABLE IF NOT EXISTS usage_events (id bigserial PRIMARY KEY, namespace text NOT NULL REFERENCES namespaces(name), skill text NOT NULL, version text NOT NULL, subject text NOT NULL, latency_ms integer NOT NULL CHECK(latency_ms BETWEEN 0 AND 3600000), success boolean NOT NULL, estimated_tokens_saved integer NOT NULL CHECK(estimated_tokens_saved BETWEEN 0 AND 10000000), estimated_cost_usd numeric(12,6) NOT NULL CHECK(estimated_cost_usd BETWEEN 0 AND 1000000), at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS usage_namespace_at ON usage_events(namespace,at DESC);
`

type App struct {
	db                        *pgxpool.Pool
	verifier, loginVerifier   *oidc.IDTokenVerifier
	devToken, mode, publicURL string
	registration, osvEnabled  bool
	oauth                     *oauth2.Config
}
type actor struct{ Subject string }
type scanResult struct {
	Score    int      `json:"score"`
	Findings []string `json:"findings"`
	Engine   string   `json:"engine"`
	Coverage []string `json:"coverage"`
}

var identifier = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var version = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?$`)

func New(ctx context.Context) (*App, error) {
	if os.Getenv("DATABASE_URL") == "" {
		return nil, errors.New("DATABASE_URL required")
	}
	mode := os.Getenv("AUTH_MODE")
	if mode == "" {
		mode = "local"
	}
	if mode != "local" && mode != "oidc" && mode != "hybrid" && mode != "dev" {
		return nil, errors.New("AUTH_MODE must be local, hybrid, oidc, or dev")
	}
	publicURL := os.Getenv("PUBLIC_URL")
	if publicURL == "" {
		publicURL = "http://localhost:8080"
	}
	if err := validatePublicURL(publicURL); err != nil {
		return nil, err
	}
	app := &App{mode: mode, publicURL: publicURL, registration: os.Getenv("REGISTRATION_ENABLED") != "false", osvEnabled: os.Getenv("SCAN_OSV") == "true"}
	if mode == "dev" {
		app.devToken = os.Getenv("DEV_TOKEN")
		if len(app.devToken) < 24 {
			return nil, errors.New("DEV_TOKEN must have at least 24 characters")
		}
	}
	if mode == "oidc" || mode == "hybrid" {
		for _, k := range []string{"OIDC_ISSUER", "OIDC_CLIENT_ID"} {
			if os.Getenv(k) == "" {
				return nil, fmt.Errorf("%s required", k)
			}
		}
		provider, err := oidc.NewProvider(ctx, os.Getenv("OIDC_ISSUER"))
		if err != nil {
			return nil, err
		}
		clientID := os.Getenv("OIDC_CLIENT_ID")
		audience := os.Getenv("OIDC_AUDIENCE")
		if audience == "" {
			audience = clientID
		}
		app.verifier = provider.Verifier(&oidc.Config{ClientID: audience})
		app.loginVerifier = provider.Verifier(&oidc.Config{ClientID: clientID})
		app.oauth = &oauth2.Config{ClientID: clientID, ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"), Endpoint: provider.Endpoint(), RedirectURL: publicURL + "/auth/oidc/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}
	}

	db, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return nil, err
	}
	if err = db.Ping(ctx); err != nil {
		db.Close()
		return nil, err
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		db.Close()
		return nil, err
	}
	defer tx.Rollback(ctx)
	// Serialize schema initialization when multiple replicas start together.
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(741923105)"); err != nil {
		_ = tx.Rollback(ctx)
		db.Close()
		return nil, err
	}
	for _, statement := range strings.Split(schema+authSchema, ";") {
		if strings.TrimSpace(statement) == "" {
			continue
		}
		if _, err = tx.Exec(ctx, statement); err != nil {
			_ = tx.Rollback(ctx)
			db.Close()
			return nil, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		db.Close()
		return nil, err
	}

	app.db = db
	return app, nil
}
func (a *App) Close() { a.db.Close() }
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	mux.HandleFunc("GET /v1/mode", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{"mode": "free", "license_required": false, "features": []string{"registry", "scan", "approval", "audit", "usage", "ui", "local-auth", "oidc"}})
	})
	mux.HandleFunc("POST /v1/namespaces", a.auth(a.createNamespace))
	mux.HandleFunc("PUT /v1/namespaces/{ns}/members/{sub}", a.auth(a.setMember))
	mux.HandleFunc("POST /v1/namespaces/{ns}/skills/{skill}/versions/{version}", a.auth(a.upload))
	mux.HandleFunc("GET /v1/namespaces/{ns}/skills", a.auth(a.list))
	mux.HandleFunc("GET /v1/namespaces/{ns}/skills/{skill}/versions/{version}", a.auth(a.download))
	mux.HandleFunc("POST /v1/namespaces/{ns}/skills/{skill}/versions/{version}/approve", a.auth(a.approve))
	mux.HandleFunc("GET /v1/namespaces/{ns}/audit", a.auth(a.audit))
	mux.HandleFunc("POST /v1/namespaces/{ns}/usage", a.auth(a.recordUsage))
	mux.HandleFunc("GET /v1/namespaces/{ns}/usage", a.auth(a.usage))
	a.routes(mux)
	return a.secure(http.MaxBytesHandler(mux, 12<<20))
}

type endpoint func(http.ResponseWriter, *http.Request, actor)

func respond(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter, code int, msg string) {
	respond(w, code, map[string]string{"error": msg})
}
func validPath(r *http.Request) bool {
	return identifier.MatchString(r.PathValue("ns")) && (r.PathValue("skill") == "" || identifier.MatchString(r.PathValue("skill")))
}
func (a *App) allowed(r *http.Request, u actor, minimum string) bool {
	if !validPath(r) {
		return false
	}
	var role string
	err := a.db.QueryRow(r.Context(), "SELECT role FROM memberships WHERE namespace=$1 AND subject=$2", r.PathValue("ns"), u.Subject).Scan(&role)
	if err != nil {
		return false
	}
	if minimum == "reader" {
		return true
	}
	if minimum == "publisher" {
		return role == "publisher" || role == "admin"
	}
	return role == "admin"
}
func (a *App) log(ctx context.Context, u actor, action, ns, skill string, detail any) {
	b, _ := json.Marshal(detail)
	_, _ = a.db.Exec(ctx, "INSERT INTO audit(subject,action,namespace,skill,detail) VALUES($1,$2,$3,$4,$5)", u.Subject, action, ns, skill, b)
}
func (a *App) createNamespace(w http.ResponseWriter, r *http.Request, u actor) {
	var v struct {
		Name string `json:"name"`
	}
	if json.NewDecoder(r.Body).Decode(&v) != nil || !identifier.MatchString(v.Name) {
		problem(w, 400, "invalid namespace")
		return
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer tx.Rollback(r.Context())
	_, err = tx.Exec(r.Context(), "INSERT INTO namespaces(name) VALUES($1)", v.Name)
	if err != nil {
		problem(w, 409, "namespace exists")
		return
	}
	_, err = tx.Exec(r.Context(), "INSERT INTO memberships(namespace,subject,role) VALUES($1,$2,'admin')", v.Name, u.Subject)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	_, err = tx.Exec(r.Context(), "INSERT INTO audit(subject,action,namespace) VALUES($1,'namespace.create',$2)", u.Subject, v.Name)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	if tx.Commit(r.Context()) != nil {
		problem(w, 500, "database error")
		return
	}
	respond(w, 201, v)
}
func (a *App) setMember(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.allowed(r, u, "admin") {
		problem(w, 403, "forbidden")
		return
	}
	var v struct {
		Role string `json:"role"`
	}
	if json.NewDecoder(r.Body).Decode(&v) != nil || (v.Role != "reader" && v.Role != "publisher" && v.Role != "admin") || r.PathValue("sub") == "" || (r.PathValue("sub") == u.Subject && v.Role != "admin") {
		problem(w, 400, "invalid member")
		return
	}
	_, err := a.db.Exec(r.Context(), "INSERT INTO memberships(namespace,subject,role) VALUES($1,$2,$3) ON CONFLICT(namespace,subject) DO UPDATE SET role=EXCLUDED.role", r.PathValue("ns"), r.PathValue("sub"), v.Role)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	a.log(r.Context(), u, "member.set", r.PathValue("ns"), "", map[string]string{"subject": r.PathValue("sub"), "role": v.Role})
	w.WriteHeader(204)
}
func inspect(data []byte) (scanResult, error) {
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return scanResult{}, err
	}
	result := scanResult{Score: 100, Findings: []string{}, Engine: "static-rules-v2", Coverage: []string{"archive-integrity", "prompt-patterns", "script-patterns", "dependency-manifests"}}
	skillMD := false
	total := int64(0)
	seen := map[string]bool{}
	hasScript := false
	hasLock := false
	for _, f := range z.File {
		if len(z.File) > 128 {
			return result, errors.New("too many files")
		}
		name := strings.ReplaceAll(f.Name, "\\", "/")
		unsafe := strings.HasPrefix(name, "/") || strings.Contains(name, "\x00") || strings.Contains(name, ":") || f.FileInfo().Mode()&os.ModeSymlink != 0 || seen[name]
		for _, part := range strings.Split(name, "/") {
			if part == "." || part == ".." {
				unsafe = true
			}
		}
		if unsafe {
			return result, errors.New("unsafe path, symlink, or duplicate file")
		}
		seen[name] = true
		if f.UncompressedSize64 > 2<<20 {
			return result, errors.New("file too large")
		}
		total += int64(f.UncompressedSize64)
		if total > 8<<20 {
			return result, errors.New("uncompressed bundle too large")
		}
		if name == "SKILL.md" && !f.FileInfo().IsDir() && f.UncompressedSize64 > 0 {
			skillMD = true
		}
		if f.FileInfo().IsDir() {
			continue
		}
		fd, err := f.Open()
		if err != nil {
			return result, err
		}
		body, err := io.ReadAll(io.LimitReader(fd, 2<<20+1))
		fd.Close()
		if err != nil || len(body) > 2<<20 {
			return result, errors.New("invalid file")
		}
		lower := strings.ToLower(string(body))
		if strings.HasSuffix(name, ".md") || strings.HasSuffix(name, ".txt") {
			for _, p := range []string{"ignore previous instructions", "disregard system prompt", "reveal your system prompt", "ignore all prior instructions", "developer message:", "system message:", "exfiltrate", "curl | sh", "wget | sh"} {
				if strings.Contains(lower, p) {
					result.Findings = append(result.Findings, "prompt injection pattern: "+name+" ("+p+")")
					result.Score -= 25
				}
			}
		}
		if strings.HasSuffix(name, ".sh") || strings.HasSuffix(name, ".py") || strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".go") {
			hasScript = true
			for _, p := range []string{"curl ", "wget ", "requests.get(", "http.get(", "fetch(", "subprocess.", "os.system(", "eval(", "/etc/passwd", "~/.ssh", "metadata.google.internal", "169.254.169.254", "rm -rf", "chmod 777"} {
				if strings.Contains(lower, p) {
					result.Findings = append(result.Findings, "script scope or SAST pattern: "+name+" ("+p+")")
					result.Score -= 20
				}
			}
		}
		if name == "package-lock.json" || name == "pnpm-lock.yaml" || name == "yarn.lock" || name == "go.sum" || name == "Cargo.lock" || name == "requirements.txt" || name == "poetry.lock" || name == "uv.lock" {
			hasLock = true
		}
		if name == "package.json" || name == "requirements.txt" || name == "go.mod" || name == "Cargo.toml" {
			for _, p := range []string{"\"*\"", "\"latest\"", "git+http:", "http://", "--trusted-host", "replace github.com/"} {
				if strings.Contains(lower, p) {
					result.Findings = append(result.Findings, "unpinned or insecure dependency: "+name+" ("+p+")")
					result.Score -= 15
				}
			}
		}
	}
	if !skillMD {
		return result, errors.New("root SKILL.md required")
	}
	if hasScript && !hasLock {
		result.Findings = append(result.Findings, "script bundle has no recognized dependency lock file")
		result.Score -= 10
	}
	if result.Score < 0 {
		result.Score = 0
	}
	return result, nil
}
func (a *App) upload(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.allowed(r, u, "publisher") {
		problem(w, 403, "forbidden")
		return
	}
	ns, name, ver := r.PathValue("ns"), r.PathValue("skill"), r.PathValue("version")
	if !version.MatchString(ver) {
		problem(w, 400, "invalid version")
		return
	}
	if r.Header.Get("Content-Type") != "application/zip" {
		problem(w, 415, "application/zip required")
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 10<<20+1))
	if err != nil || len(data) > 10<<20 {
		problem(w, 413, "bundle too large")
		return
	}
	scan, err := a.scan(r.Context(), data)
	if err != nil {
		problem(w, 400, err.Error())
		return
	}
	b, _ := json.Marshal(scan)
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	status := "quarantined"
	_, err = a.db.Exec(r.Context(), "INSERT INTO skills(namespace,name,version,sha256,bundle,scan,status,uploaded_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", ns, name, ver, digest, data, b, status, u.Subject)
	if err != nil {
		problem(w, 409, "version exists or database error")
		return
	}
	a.log(r.Context(), u, "skill.upload", ns, name, map[string]any{"version": ver, "sha256": digest, "scan": scan})
	respond(w, 201, map[string]any{"status": status, "sha256": digest, "scan": scan})
}
func (a *App) list(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.allowed(r, u, "reader") {
		problem(w, 403, "forbidden")
		return
	}
	rows, err := a.db.Query(r.Context(), "SELECT name,version,sha256,status,scan,created_at FROM skills WHERE namespace=$1 AND ($2='' OR name ILIKE '%'||$2||'%') AND ($3='' OR status=$3) ORDER BY created_at DESC,name,version LIMIT $4 OFFSET $5", r.PathValue("ns"), r.URL.Query().Get("q"), r.URL.Query().Get("status"), pageLimit(r), pageOffset(r))
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []any{}
	for rows.Next() {
		var name, ver, hash, status string
		var scan json.RawMessage
		var at time.Time
		if rows.Scan(&name, &ver, &hash, &status, &scan, &at) != nil {
			problem(w, 500, "database error")
			return
		}
		items = append(items, map[string]any{"name": name, "version": ver, "sha256": hash, "status": status, "scan": scan, "created_at": at})
	}
	if rows.Err() != nil {
		problem(w, 500, "database error")
		return
	}
	respond(w, 200, items)
}
func (a *App) download(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.allowed(r, u, "reader") {
		problem(w, 403, "forbidden")
		return
	}
	var data []byte
	var hash string
	err := a.db.QueryRow(r.Context(), "SELECT bundle,sha256 FROM skills WHERE namespace=$1 AND name=$2 AND version=$3 AND status='published'", r.PathValue("ns"), r.PathValue("skill"), r.PathValue("version")).Scan(&data, &hash)
	if err != nil {
		problem(w, 404, "published version not found")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("X-Content-SHA256", hash)
	w.Header().Set("Content-Disposition", "attachment; filename=skill.zip")
	_, _ = w.Write(data)
	a.log(r.Context(), u, "skill.download", r.PathValue("ns"), r.PathValue("skill"), map[string]string{"version": r.PathValue("version")})
}
func (a *App) approve(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.allowed(r, u, "admin") {
		problem(w, 403, "forbidden")
		return
	}
	tag, err := a.db.Exec(r.Context(), "UPDATE skills SET status='published' WHERE namespace=$1 AND name=$2 AND version=$3 AND status='quarantined' AND (scan->>'score')::int = 100 AND jsonb_array_length(scan->'findings')=0", r.PathValue("ns"), r.PathValue("skill"), r.PathValue("version"))
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 409, "missing, already reviewed, or scan has findings")
		return
	}
	a.log(r.Context(), u, "skill.approve", r.PathValue("ns"), r.PathValue("skill"), map[string]string{"version": r.PathValue("version")})
	w.WriteHeader(204)
}
func (a *App) audit(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.allowed(r, u, "admin") {
		problem(w, 403, "forbidden")
		return
	}
	rows, err := a.db.Query(r.Context(), "SELECT id,at,subject,action,skill,detail FROM audit WHERE namespace=$1 ORDER BY id DESC LIMIT 100", r.PathValue("ns"))
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []any{}
	for rows.Next() {
		var id int64
		var at time.Time
		var sub, action, skill string
		var detail json.RawMessage
		if rows.Scan(&id, &at, &sub, &action, &skill, &detail) != nil {
			problem(w, 500, "database error")
			return
		}
		items = append(items, map[string]any{"id": id, "at": at, "subject": sub, "action": action, "skill": skill, "detail": detail})
	}
	if rows.Err() != nil {
		problem(w, 500, "database error")
		return
	}
	respond(w, 200, items)
}
func (a *App) recordUsage(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.allowed(r, u, "reader") {
		problem(w, 403, "forbidden")
		return
	}
	var v struct {
		Skill                string  `json:"skill"`
		Version              string  `json:"version"`
		LatencyMS            int     `json:"latency_ms"`
		Success              bool    `json:"success"`
		EstimatedTokensSaved int     `json:"estimated_tokens_saved"`
		EstimatedCostUSD     float64 `json:"estimated_cost_usd"`
	}
	if json.NewDecoder(r.Body).Decode(&v) != nil || !identifier.MatchString(v.Skill) || !version.MatchString(v.Version) || v.LatencyMS < 0 || v.LatencyMS > 3600000 || v.EstimatedTokensSaved < 0 || v.EstimatedTokensSaved > 10000000 || v.EstimatedCostUSD < 0 || v.EstimatedCostUSD > 1000000 {
		problem(w, 400, "invalid usage event")
		return
	}
	var exists bool
	err := a.db.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM skills WHERE namespace=$1 AND name=$2 AND version=$3 AND status='published')", r.PathValue("ns"), v.Skill, v.Version).Scan(&exists)
	if err != nil || !exists {
		problem(w, 404, "published skill not found")
		return
	}
	_, err = a.db.Exec(r.Context(), "INSERT INTO usage_events(namespace,skill,version,subject,latency_ms,success,estimated_tokens_saved,estimated_cost_usd) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", r.PathValue("ns"), v.Skill, v.Version, u.Subject, v.LatencyMS, v.Success, v.EstimatedTokensSaved, v.EstimatedCostUSD)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	w.WriteHeader(204)
}
func (a *App) usage(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.allowed(r, u, "admin") {
		problem(w, 403, "forbidden")
		return
	}
	rows, err := a.db.Query(r.Context(), "SELECT skill,version,count(*),round(avg(latency_ms),1),round(100.0*avg(CASE WHEN success THEN 1 ELSE 0 END),1),sum(estimated_tokens_saved),sum(estimated_cost_usd)::text FROM usage_events WHERE namespace=$1 AND at >= now()-interval '30 days' GROUP BY skill,version ORDER BY count(*) DESC LIMIT 100", r.PathValue("ns"))
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []any{}
	for rows.Next() {
		var skill, ver, cost string
		var calls, tokens int64
		var latency, success float64
		if rows.Scan(&skill, &ver, &calls, &latency, &success, &tokens, &cost) != nil {
			problem(w, 500, "database error")
			return
		}
		items = append(items, map[string]any{"skill": skill, "version": ver, "calls": calls, "avg_latency_ms": latency, "success_pct": success, "estimated_tokens_saved": tokens, "estimated_cost_usd": cost})
	}
	if rows.Err() != nil {
		problem(w, 500, "database error")
		return
	}
	respond(w, 200, map[string]any{"period": "30d", "source": "client-reported", "items": items})
}
