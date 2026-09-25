package registry

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"
)

type dependency struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Version   string `json:"version"`
}

var pinnedPython = regexp.MustCompile(`^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?==([A-Za-z0-9_.+!-]+)$`)
var goDependency = regexp.MustCompile(`(?m)^\s*(?:require\s+)?([a-zA-Z0-9._~/-]+)\s+(v[^\s]+)`)

// Only exact versions are queried. Unsupported manifests are reported, never
// silently treated as evidence that dependency scanning succeeded.
func dependencies(name string, body []byte) ([]dependency, []string) {
	deps := []dependency{}
	issues := []string{}
	switch path.Base(name) {
	case "requirements.txt":
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(strings.SplitN(line, " #", 2)[0])
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			line = strings.TrimSpace(strings.SplitN(line, ";", 2)[0])
			m := pinnedPython.FindStringSubmatch(line)
			if m == nil {
				issues = append(issues, "unsupported or unpinned Python dependency in "+name)
				continue
			}
			deps = append(deps, dependency{m[1], "PyPI", m[2]})
		}
	case "go.mod":
		for _, m := range goDependency.FindAllStringSubmatch(string(body), -1) {
			deps = append(deps, dependency{m[1], "Go", m[2]})
		}
		if strings.Contains(string(body), "replace ") {
			issues = append(issues, "Go replace directives require manual review: "+name)
		}
	case "package-lock.json":
		var lock struct {
			LockfileVersion int `json:"lockfileVersion"`
			Packages        map[string]struct {
				Name, Version string
				Link          bool
			} `json:"packages"`
		}
		if json.Unmarshal(body, &lock) != nil || lock.LockfileVersion < 2 || lock.Packages == nil {
			issues = append(issues, "invalid or unsupported npm lockfile (v2/v3 required): "+name)
			break
		}
		for location, p := range lock.Packages {
			if location == "" {
				continue
			}
			n := p.Name
			if n == "" {
				parts := strings.Split(location, "node_modules/")
				n = parts[len(parts)-1]
			}
			if p.Link || p.Version == "" || !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+`).MatchString(p.Version) {
				issues = append(issues, "non-registry npm dependency: "+location)
				continue
			}
			deps = append(deps, dependency{n, "npm", p.Version})
		}
	case "Cargo.toml", "Cargo.lock", "poetry.lock", "uv.lock", "pnpm-lock.yaml", "yarn.lock":
		issues = append(issues, "dependency advisory parser not supported: "+name)
	}
	return deps, issues
}
func (a *App) scan(ctx context.Context, data []byte) (scanResult, error) {
	result, err := inspect(data)
	if err != nil {
		return result, err
	}
	result.Engine = "static-rules-v3"
	z, _ := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	deps := []dependency{}
	hasNPM, hasNPMLock := false, false
	for _, f := range z.File {
		if f.FileInfo().IsDir() {
			continue
		}
		fd, err := f.Open()
		if err != nil {
			return result, err
		}
		body, err := io.ReadAll(io.LimitReader(fd, 2<<20+1))
		fd.Close()
		if err != nil {
			return result, err
		}
		for _, hidden := range []string{"\u200b", "\u202e", "\u2066", "\u2067", "\u2068"} {
			if strings.Contains(string(body), hidden) {
				result.Findings = append(result.Findings, "hidden Unicode control character: "+f.Name)
				break
			}
		}
		if a.osvEnabled {
			d, issues := dependencies(f.Name, body)
			deps = append(deps, d...)
			result.Findings = append(result.Findings, issues...)
			if path.Base(f.Name) == "package.json" {
				hasNPM = true
			}
			if path.Base(f.Name) == "package-lock.json" {
				hasNPMLock = true
			}
		}
	}
	if a.osvEnabled {
		result.Coverage = append(result.Coverage, "osv: npm-lock-v2/v3, pinned-requirements, go.mod")
		if hasNPM && !hasNPMLock {
			result.Findings = append(result.Findings, "npm advisory scanning requires package-lock.json")
		}
		findings, err := queryOSV(ctx, "https://api.osv.dev/v1/querybatch", deps)
		if err != nil {
			result.Findings = append(result.Findings, "dependency advisory scan incomplete; rescan required")
		} else {
			result.Findings = append(result.Findings, findings...)
		}
	} else {
		result.Coverage = append(result.Coverage, "dependency advisories disabled (SCAN_OSV=false)")
	}
	if len(result.Findings) > 0 && result.Score == 100 {
		result.Score = 75
	}
	return result, nil
}
func queryOSV(ctx context.Context, endpoint string, deps []dependency) ([]string, error) {
	if len(deps) == 0 {
		return nil, nil
	}
	if len(deps) > 1000 {
		return nil, fmt.Errorf("dependency limit exceeded")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	queries := []any{}
	for _, d := range deps {
		queries = append(queries, map[string]any{"package": map[string]string{"name": d.Name, "ecosystem": d.Ecosystem}, "version": d.Version})
	}
	body, _ := json.Marshal(map[string]any{"queries": queries})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("advisory service status %d", resp.StatusCode)
	}
	var result struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
			Next string `json:"next_page_token"`
		} `json:"results"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&result); err != nil {
		return nil, err
	}
	if len(result.Results) != len(deps) {
		return nil, fmt.Errorf("incomplete response")
	}
	findings := []string{}
	for i, r := range result.Results {
		for _, v := range r.Vulns {
			findings = append(findings, fmt.Sprintf("dependency vulnerability: %s %s@%s (%s)", deps[i].Ecosystem, deps[i].Name, deps[i].Version, v.ID))
		}
		if r.Next != "" {
			findings = append(findings, "additional advisories exist for "+deps[i].Name+"; publication blocked")
		}
	}
	return findings, nil
}
