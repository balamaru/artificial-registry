package registry

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func (a *App) updateSkill(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.allowed(r, u, "update") {
		problem(w, 403, "forbidden")
		return
	}
	if !version.MatchString(r.PathValue("version")) {
		problem(w, 400, "invalid version")
		return
	}
	expected := strings.Trim(r.Header.Get("If-Match"), `"`)
	if expected == "" {
		problem(w, 428, "If-Match with current SHA-256 required")
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
	body, _ := json.Marshal(scan)
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer tx.Rollback(r.Context())
	var old string
	var revision int
	if tx.QueryRow(r.Context(), "SELECT sha256 FROM skills WHERE namespace=$1 AND name=$2 AND version=$3 FOR UPDATE", r.PathValue("ns"), r.PathValue("skill"), r.PathValue("version")).Scan(&old) != nil {
		problem(w, 404, "version not found")
		return
	}
	if old != expected {
		problem(w, 412, "version changed; refresh before updating")
		return
	}
	err = tx.QueryRow(r.Context(), "UPDATE skills SET bundle=$4,sha256=$5,scan=$6,status='quarantined',uploaded_by=$7,updated_at=now(),revision=revision+1 WHERE namespace=$1 AND name=$2 AND version=$3 RETURNING revision", r.PathValue("ns"), r.PathValue("skill"), r.PathValue("version"), data, digest, body, u.Subject).Scan(&revision)
	detail := map[string]any{"version": r.PathValue("version"), "previous_sha256": old, "sha256": digest, "revision": revision}
	if err != nil || auditTx(r.Context(), tx, u, "skill.update", r.PathValue("ns"), r.PathValue("skill"), detail) != nil || tx.Commit(r.Context()) != nil {
		problem(w, 500, "database error")
		return
	}
	respond(w, 200, map[string]any{"sha256": digest, "revision": revision, "status": "quarantined", "scan": scan})
}
func (a *App) deleteSkill(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.allowed(r, u, "delete") {
		problem(w, 403, "forbidden")
		return
	}
	ver := r.PathValue("version")
	expected := strings.Trim(r.Header.Get("If-Match"), `"`)
	if ver != "" && expected == "" {
		problem(w, 428, "If-Match with current SHA-256 required")
		return
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer tx.Rollback(r.Context())
	rows, err := tx.Query(r.Context(), "SELECT version,sha256 FROM skills WHERE namespace=$1 AND name=$2 AND ($3='' OR version=$3) ORDER BY version FOR UPDATE", r.PathValue("ns"), r.PathValue("skill"), ver)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	versions := []string{}
	hashes := map[string]string{}
	for rows.Next() {
		var version, hash string
		if rows.Scan(&version, &hash) != nil {
			rows.Close()
			problem(w, 500, "database error")
			return
		}
		versions = append(versions, version)
		hashes[version] = hash
	}
	rows.Close()
	if rows.Err() != nil {
		problem(w, 500, "database error")
		return
	}
	if len(versions) == 0 {
		problem(w, 404, "skill version not found")
		return
	}
	if ver != "" && hashes[ver] != expected {
		problem(w, 412, "version changed; refresh before deleting")
		return
	}
	// Delete only the locked snapshot. Concurrent new versions are preserved.
	_, err = tx.Exec(r.Context(), "DELETE FROM skills WHERE namespace=$1 AND name=$2 AND version=ANY($3)", r.PathValue("ns"), r.PathValue("skill"), versions)
	if err != nil || auditTx(r.Context(), tx, u, "skill.delete", r.PathValue("ns"), r.PathValue("skill"), map[string]any{"versions": versions, "sha256": hashes}) != nil || tx.Commit(r.Context()) != nil {
		problem(w, 500, "database error")
		return
	}
	w.WriteHeader(204)
}
