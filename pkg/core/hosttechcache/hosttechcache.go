package hosttechcache

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Masterminds/semver/v3"
)

// knownServerTags maps server header substrings to their canonical tag(s).
// Only Apache-family servers are "known" — their server header alone is
// sufficient to identify the tech stack (Apache → likely Tomcat/OFBiz/etc.).
// Generic servers (Tornado, Nginx, IIS, etc.) are intentionally NOT listed
// here so they fall through to app-URL detection per the diagram.
var knownServerTags = map[string][]string{
	"apache": {"apache"},
	"coyote": {"apache", "tomcat"},
	"tomcat": {"apache", "tomcat"},
}

// normalizeHost strips any http:// or https:// scheme so we always store and
// look up cache entries under the bare "host[:port]" form.  This prevents
// double-scheme bugs when value.Input arrives pre-normalised from httpx.
func normalizeHost(host string) string {
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	// Strip any trailing path (keep only host:port)
	if idx := strings.IndexByte(host, '/'); idx != -1 {
		host = host[:idx]
	}
	return host
}

// ProbeResult is the outcome of a one-time HTTP probe for a host.
type ProbeResult int

const (
	ProbeUnknown        ProbeResult = iota
	ProbeHasServerMatch             // server header matched a known tag set
	ProbeHasServerNoMatch           // server header present but unrecognised (Tornado, etc.)
	ProbeNoServerHeader             // no Server header at all
)

// TechHint holds everything we know about the tech stack of a single host.
type TechHint struct {
	// Probe outcome – drives the filtering logic from the diagram.
	ProbeResult ProbeResult

	// Layer 1 – server header
	Server        string
	ServerVersion string

	// Layer 2 – framework inferred from server
	Framework        string
	FrameworkVersion string

	// Layer 3 – application detected via URL probes
	Application string
	AppVersion  string

	// All tags that are valid for template matching on this host.
	// Populated differently depending on which branch of the diagram we took:
	//   • ProbeHasServerMatch  → server-derived tags only (no deep scan needed)
	//   • ProbeHasServerNoMatch → app-URL scan tags (or empty → allow all)
	//   • ProbeNoServerHeader  → app-URL scan tags (or empty → allow all)
	Tags []string

	// Whether app-URL detection has already been attempted for this host.
	AppDetectionDone bool
}

// HostTechCache stores per-host TechHints and drives the diagram logic.
type HostTechCache struct {
	mu    sync.RWMutex
	cache map[string]*TechHint
}

func New() *HostTechCache {
	return &HostTechCache{
		cache: make(map[string]*TechHint),
	}
}

// HasHint returns true when we have already probed this host at the server
// level (i.e. the one-time HTTP probe has been fired).
func (h *HostTechCache) HasHint(host string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	hint, ok := h.cache[normalizeHost(host)]
	return ok && hint.ProbeResult != ProbeUnknown
}

// GetHint returns the stored hint (may be nil).
func (h *HostTechCache) GetHint(host string) (*TechHint, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	hint, ok := h.cache[normalizeHost(host)]
	return hint, ok
}

// ─────────────────────────────────────────────────────────────────────────────
// Recording probe outcomes  (called from executor after the one-time GET)
// ─────────────────────────────────────────────────────────────────────────────

// RecordServerHeader is called when the one-time probe finds a Server header.
// It implements the LEFT branch of the diagram:
//
//	Server header present
//	  → matched to known app tags  → ProbeHasServerMatch  (use cached tags)
//	  → not matched                → ProbeHasServerNoMatch (run app-URL detection later)
func (h *HostTechCache) RecordServerHeader(host, serverHeader string) {
	host = normalizeHost(host)
	server, version := ParseServerHeader(serverHeader)
	framework := MapServerToFramework(server)
	tags := matchKnownServerTags(server)

	result := ProbeHasServerNoMatch
	if len(tags) > 0 {
		result = ProbeHasServerMatch
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	h.cache[host] = &TechHint{
		ProbeResult:   result,
		Server:        server,
		ServerVersion: version,
		Framework:     framework,
		Tags:          tags,
	}
}

// RecordNoServerHeader is called when the one-time probe finds NO Server header.
// This is the RIGHT branch of the diagram:
//
//	No Server header → run all possible app-URL detection
func (h *HostTechCache) RecordNoServerHeader(host string) {
	host = normalizeHost(host)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cache[host] = &TechHint{
		ProbeResult: ProbeNoServerHeader,
	}
}

// RecordAppDetection stores the result of app-URL detection and updates tags.
// Used for both ProbeHasServerNoMatch and ProbeNoServerHeader paths.
func (h *HostTechCache) RecordAppDetection(host, app, appVersion string, appTags []string) {
	host = normalizeHost(host)
	h.mu.Lock()
	defer h.mu.Unlock()
	hint, ok := h.cache[host]
	if !ok {
		hint = &TechHint{}
		h.cache[host] = hint
	}
	hint.Application = app
	hint.AppVersion = appVersion
	hint.AppDetectionDone = true

	// Merge app tags with any existing server tags.
	existing := make(map[string]struct{}, len(hint.Tags))
	for _, t := range hint.Tags {
		existing[t] = struct{}{}
	}
	for _, t := range appTags {
		if _, seen := existing[t]; !seen {
			hint.Tags = append(hint.Tags, t)
		}
	}
}

// RecordTemplateMatch is called when a template matches; we learn its tags.
func (h *HostTechCache) RecordTemplateMatch(host string, tags []string) {
	host = normalizeHost(host)
	h.mu.Lock()
	defer h.mu.Unlock()
	hint, ok := h.cache[host]
	if !ok {
		return
	}
	existing := make(map[string]struct{}, len(hint.Tags))
	for _, t := range hint.Tags {
		existing[t] = struct{}{}
	}
	for _, t := range tags {
		if _, seen := existing[t]; !seen {
			hint.Tags = append(hint.Tags, t)
		}
	}
}

// GetServerHeader returns the raw server header value (empty string if unknown).
func (h *HostTechCache) GetServerHeader(host string) string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if hint, ok := h.cache[normalizeHost(host)]; ok {
		return hint.Server
	}
	return ""
}

// GetVersion returns the most-specific version we know for a host.
func (h *HostTechCache) GetVersion(host string) string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	hint, ok := h.cache[normalizeHost(host)]
	if !ok {
		return ""
	}
	if hint.AppVersion != "" {
		return hint.AppVersion
	}
	if hint.FrameworkVersion != "" {
		return hint.FrameworkVersion
	}
	return hint.ServerVersion
}

// ─────────────────────────────────────────────────────────────────────────────
// Core decision: ShouldSkipTemplateWithVersion
// Implements all branches of the diagram.
// ─────────────────────────────────────────────────────────────────────────────

// ShouldSkipTemplateWithVersion returns true when this template should be
// skipped for the given host.  It mirrors the full diagram:
//
// Branch A – ProbeHasServerMatch
//
//	Server header matched a known tag set → use only those cached tags.
//	Allow template only if its tags overlap with the cached server tags
//	(plus version check when present).
//
// Branch B – ProbeHasServerNoMatch
//
//	Server header was present but unrecognised (Tornado/IIS/Nginx etc.).
//	App-URL detection should have run already (triggered by the executor).
//	  • App match   → allow only templates whose tags match app tags.
//	  • No app match → allow ALL templates (safe fallback).
//
// Branch C – ProbeNoServerHeader
//
//	No server header.  App-URL detection should have run already.
//	  • App match   → allow only templates whose tags match app tags.
//	  • No app match → allow ALL templates (safe fallback).
func (h *HostTechCache) ShouldSkipTemplateWithVersion(
	host string,
	templateTags []string,
	versionRanges map[string]interface{},
) bool {
	h.mu.RLock()
	hint, ok := h.cache[normalizeHost(host)]
	h.mu.RUnlock()

	// No probe result at all → allow everything.
	if !ok || hint.ProbeResult == ProbeUnknown {
		return false
	}

	switch hint.ProbeResult {

	// ── Branch A: server header matched a known Apache-family tag ────────────
	// We know the server is Apache/Tomcat. Only skip templates that have
	// explicit tech tags AND those tags don't overlap with apache/tomcat.
	// Generic tagless templates already passed the check above.
	case ProbeHasServerMatch:
		if !tagsOverlap(templateTags, hint.Tags) {
			return true // skip – clearly a different tech stack
		}
		return !versionAllowed(hint, versionRanges)

	// ── Branch B: server header present but unrecognised (Tornado/Nginx/IIS) ─
	// App-URL detection runs to try to identify the specific application.
	case ProbeHasServerNoMatch:
		if !hint.AppDetectionDone {
			return false // detection not done yet → allow
		}
		if hint.Application != "" {
			// We identified a specific app (Airflow/OFBiz/Druid/CXF).
			// Only run templates whose tags match the detected app.
			if !tagsOverlap(templateTags, hint.Tags) {
				return true
			}
			return !versionAllowed(hint, versionRanges)
		}
		// No specific app detected → allow ALL templates (safe fallback).
		return false

	// ── Branch C: no server header at all ───────────────────────────────────
	case ProbeNoServerHeader:
		if !hint.AppDetectionDone {
			return false
		}
		if hint.Application != "" {
			if !tagsOverlap(templateTags, hint.Tags) {
				return true
			}
			return !versionAllowed(hint, versionRanges)
		}
		// No app detected → allow ALL templates.
		return false
	}

	return false
}

// ShouldSkipTemplate is a convenience wrapper for callers (e.g. tmplexec)
// that do not have version-range metadata. It delegates to
// ShouldSkipTemplateWithVersion with no version constraints.
func (h *HostTechCache) ShouldSkipTemplate(host string, templateTags []string) bool {
	return h.ShouldSkipTemplateWithVersion(host, templateTags, nil)
}

// NeedsAppDetection returns true when the host is in a state where we should
// run app-URL detection before the next template is evaluated.
func (h *HostTechCache) NeedsAppDetection(host string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	hint, ok := h.cache[normalizeHost(host)]
	if !ok {
		return false
	}
	if hint.AppDetectionDone {
		return false
	}
	// Both "no server header" and "server header but unrecognised" need app detection.
	return hint.ProbeResult == ProbeNoServerHeader || hint.ProbeResult == ProbeHasServerNoMatch
}

// ─────────────────────────────────────────────────────────────────────────────
// App-URL detection (unchanged from original, called from executor)
// ─────────────────────────────────────────────────────────────────────────────

// ProbeHost fires a lightweight GET at the host, reads the Server header, and
// records the outcome. This is the same logic as the executor's
// probeHostServerHeader but exposed so that non-engine callers (e.g. tmplexec)
// can trigger it directly without importing the engine package.
func (h *HostTechCache) ProbeHost(host string) {
	bareHost := normalizeHost(host) // e.g. "127.0.0.1:98" — used as cache key and for URL building

	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", "http://"+bareHost, nil)
	if err != nil {
		h.RecordNoServerHeader(bareHost)
		return
	}

	resp, err := client.Do(req)
	if err != nil || resp == nil {
		h.RecordNoServerHeader(bareHost)
		return
	}
	defer resp.Body.Close()

	serverHdr := resp.Header.Get("Server")
	if serverHdr != "" {
		h.RecordServerHeader(bareHost, serverHdr)
	} else {
		h.RecordNoServerHeader(bareHost)
	}
}

// RunAppDetection performs deep app-URL probes for a host and stores the result.
// target may include a scheme; it is normalized to bare host:port internally.
func (h *HostTechCache) RunAppDetection(target string) {
	bareHost := normalizeHost(target)
	app, version, appTags := DetectApplication(bareHost)
	h.RecordAppDetection(bareHost, app, version, appTags)
}

// DetectApplication performs application-level detection via URL probes.
func DetectApplication(target string) (app string, version string, additionalTags []string) {
	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if isAirflow, ver := detectAirflow(client, target); isAirflow {
		return "Airflow", ver, []string{"airflow", "celery", "flower", "apache"}
	}
	if isOFBiz, ver := detectOFBiz(client, target); isOFBiz {
		return "OFBiz", ver, []string{"ofbiz", "apache"}
	}
	if isDruid, ver := detectDruid(client, target); isDruid {
		return "Druid", ver, []string{"druid", "apache"}
	}
	if isCFX, ver := detectCFX(client, target); isCFX {
		return "CFX", ver, []string{"cxf", "apache", "soap", "webservice"}
	}

	return "", "", []string{}
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

// matchKnownServerTags returns the canonical tags for a server name, or nil
// if the server is not in the known list.
func matchKnownServerTags(server string) []string {
	serverLower := strings.ToLower(server)
	for keyword, tags := range knownServerTags {
		if strings.Contains(serverLower, keyword) {
			return tags
		}
	}
	return nil
}

// tagsOverlap returns true when at least one tag from templateTags is present
// in hostTags. Only cached host tags allow templates through.
func tagsOverlap(templateTags, hostTags []string) bool {
	set := make(map[string]struct{}, len(hostTags))
	for _, t := range hostTags {
		set[strings.ToLower(t)] = struct{}{}
	}
	for _, t := range templateTags {
		if _, ok := set[strings.ToLower(t)]; ok {
			return true
		}
	}
	return false
}

// versionAllowed returns true when either no version constraint is set or the
// detected version satisfies the constraint.
func versionAllowed(hint *TechHint, versionRanges map[string]interface{}) bool {
	if len(versionRanges) == 0 {
		return true
	}
	version := hint.AppVersion
	if version == "" {
		version = hint.FrameworkVersion
	}
	if version == "" {
		version = hint.ServerVersion
	}
	if version == "" {
		return true // no version detected → safe fallback: allow
	}
	return versionMatches(version, versionRanges)
}

// ─────────────────────────────────────────────────────────────────────────────
// Parsing helpers (unchanged from original)
// ─────────────────────────────────────────────────────────────────────────────

func ParseServerHeader(serverHeader string) (string, string) {
	if serverHeader == "" {
		return "", ""
	}
	parts := strings.Split(serverHeader, "/")
	if len(parts) == 1 {
		return strings.TrimSpace(parts[0]), ""
	}
	server := strings.TrimSpace(parts[0])
	versionPart := strings.TrimSpace(parts[1])
	version := strings.FieldsFunc(versionPart, func(r rune) bool {
		return r == ' ' || r == '('
	})[0]
	return server, version
}

func MapServerToFramework(server string) string {
	serverLower := strings.ToLower(server)
	if strings.Contains(serverLower, "coyote") {
		return "Tomcat"
	}
	if strings.Contains(serverLower, "tornado") {
		return "Tornado"
	}
	if strings.Contains(serverLower, "nginx") {
		return "nginx"
	}
	if strings.Contains(serverLower, "iis") {
		return "IIS"
	}
	return ""
}

// ─────────────────────────────────────────────────────────────────────────────
// App-level URL detectors (unchanged from original)
// ─────────────────────────────────────────────────────────────────────────────

func detectAirflow(client *http.Client, target string) (bool, string) {
	resp, err := client.Get("http://" + target + "/dashboard")
	if err == nil && resp.StatusCode == 200 {
		resp.Body.Close()
		resp2, err2 := client.Get("http://" + target + "/")
		if err2 == nil {
			defer resp2.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp2.Body, 8192))
			return true, extractVersion(string(body), "Celery", "Flower")
		}
		return true, ""
	}
	if resp != nil {
		resp.Body.Close()
	}

	resp, err = client.Get("http://" + target + "/api/workers")
	if err == nil && resp.StatusCode == 200 {
		resp.Body.Close()
		return true, ""
	}
	if resp != nil {
		resp.Body.Close()
	}

	resp, err = client.Get("http://" + target + "/admin/")
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		bodyStr := string(body)
		if strings.Contains(strings.ToLower(bodyStr), "airflow") {
			return true, extractVersion(bodyStr, "Airflow")
		}
	}
	if resp != nil {
		resp.Body.Close()
	}
	return false, ""
}

func detectOFBiz(client *http.Client, target string) (bool, string) {
	resp, err := client.Get("http://" + target + "/control/main")
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		if strings.Contains(strings.ToLower(string(body)), "ofbiz") {
			return true, extractVersion(string(body), "OFBiz")
		}
	}
	if resp != nil {
		resp.Body.Close()
	}

	resp, err = client.Get("http://" + target + "/catalog/control/login")
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		if strings.Contains(strings.ToLower(string(body)), "ofbiz") {
			return true, ""
		}
	}
	if resp != nil {
		resp.Body.Close()
	}

	resp, err = client.Get("http://" + target + "/webtools/control/main")
	if err == nil && resp.StatusCode == 200 {
		resp.Body.Close()
		return true, ""
	}
	if resp != nil {
		resp.Body.Close()
	}
	return false, ""
}

func detectDruid(client *http.Client, target string) (bool, string) {
	resp, err := client.Get("http://" + target + "/unified-console.html")
	if err == nil && resp.StatusCode == 200 {
		resp.Body.Close()
		resp2, err2 := client.Get("http://" + target + "/status")
		if err2 == nil {
			defer resp2.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp2.Body, 4096))
			return true, extractVersion(string(body), "version")
		}
		return true, ""
	}
	if resp != nil {
		resp.Body.Close()
	}

	resp, err = client.Get("http://" + target + "/druid/coordinator/v1/leader")
	if err == nil && resp.StatusCode == 200 {
		resp.Body.Close()
		return true, ""
	}
	if resp != nil {
		resp.Body.Close()
	}

	resp, err = client.Get("http://" + target + "/status/health")
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if strings.Contains(strings.ToLower(string(body)), "druid") {
			return true, ""
		}
	}
	if resp != nil {
		resp.Body.Close()
	}
	return false, ""
}

func detectCFX(client *http.Client, target string) (bool, string) {
	resp, err := client.Get("http://" + target + "/services")
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		bodyStr := string(body)
		if strings.Contains(strings.ToLower(bodyStr), "cxf") ||
			strings.Contains(strings.ToLower(bodyStr), "web services") {
			return true, extractVersion(bodyStr, "CXF", "Apache CXF")
		}
	}
	if resp != nil {
		resp.Body.Close()
	}

	resp, err = client.Get("http://" + target + "/test?wsdl")
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		bodyStr := strings.ToLower(string(body))
		if strings.Contains(bodyStr, "wsdl") &&
			(strings.Contains(bodyStr, "cxf") || strings.Contains(bodyStr, "soap")) {
			return true, ""
		}
	}
	if resp != nil {
		resp.Body.Close()
	}
	return false, ""
}

func extractVersion(body string, keywords ...string) string {
	bodyLower := strings.ToLower(body)
	for _, keyword := range keywords {
		keywordLower := strings.ToLower(keyword)
		patterns := []string{
			keywordLower + " version ",
			keywordLower + " v",
			keywordLower + "/",
			keywordLower + "-",
		}
		for _, pattern := range patterns {
			idx := strings.Index(bodyLower, pattern)
			if idx != -1 {
				start := idx + len(pattern)
				if start < len(body) {
					snippet := body[start:min(start+20, len(body))]
					for i, ch := range snippet {
						if !isVersionChar(ch) {
							if i > 0 {
								potentialVersion := snippet[:i]
								if strings.Contains(potentialVersion, ".") {
									return potentialVersion
								}
							}
							break
						}
					}
				}
			}
		}
	}
	return ""
}

func isVersionChar(ch rune) bool {
	return (ch >= '0' && ch <= '9') || ch == '.' || ch == '-'
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
// Version matching (unchanged from original)
// ─────────────────────────────────────────────────────────────────────────────

func versionMatches(detectedVersion string, versionRanges map[string]interface{}) bool {
	detected, err := semver.NewVersion(detectedVersion)
	if err != nil {
		return true
	}
	for rangeType, rangeValue := range versionRanges {
		switch rangeType {
		case "equals":
			for _, ver := range toStringArray(rangeValue) {
				target, err := semver.NewVersion(ver)
				if err != nil {
					continue
				}
				if detected.Equal(target) {
					return true
				}
			}
		case "less_than":
			for _, threshold := range toStringArray(rangeValue) {
				target, err := semver.NewVersion(threshold)
				if err != nil {
					continue
				}
				if detected.LessThan(target) {
					return true
				}
			}
		case "between-inclusive":
			for _, rangeStr := range toStringArray(rangeValue) {
				parts := strings.Split(rangeStr, ",")
				if len(parts) != 2 {
					continue
				}
				lo, err1 := semver.NewVersion(strings.TrimSpace(parts[0]))
				hi, err2 := semver.NewVersion(strings.TrimSpace(parts[1]))
				if err1 != nil || err2 != nil {
					continue
				}
				if (detected.Equal(lo) || detected.GreaterThan(lo)) &&
					(detected.Equal(hi) || detected.LessThan(hi)) {
					return true
				}
			}
		}
	}
	return false
}

func toStringArray(value interface{}) []string {
	switch v := value.(type) {
	case string:
		return []string{v}
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	case []string:
		return v
	default:
		return []string{}
	}
}