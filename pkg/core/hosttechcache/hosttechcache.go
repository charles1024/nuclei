package hosttechcache

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
)

// TechHint represents detected technology on a host.
type TechHint struct {
	Server        string              // "Apache-Coyote/1.1", "TornadoServer/6.0.3"
	ServerVersion string              // "1.1", "6.0.3"
	Framework     string              // "Tomcat", "Tornado"
	Application   string              // "Airflow", "OFBiz", "Druid", "CFX"
	AppVersion    string              // "1.10.10"

	// Tags are the primary tech tags detected at probe time (server header +
	// app-URL detection). These drive the initial template filtering.
	Tags map[string]struct{}

	// ExtraTags are product-specific tags learned at runtime when a template
	// matches and its product tags were NOT already in Tags.  Once populated,
	// ShouldSkipTemplate also allows templates that overlap with ExtraTags,
	// pruning the remaining work to focus on newly discovered technologies and
	// speeding up the rest of the scan.
	ExtraTags map[string]struct{}
}

// genericTags are nuclei category/severity/protocol tags that carry no
// product-specific meaning.  A tag in this set is never stored in ExtraTags
// and never used for overlap matching — only true product names are.
var genericTags = map[string]struct{}{
	// CVE tracking (product-agnostic)
	"cve": {}, "cve2016": {}, "cve2017": {}, "cve2018": {}, "cve2019": {},
	"cve2020": {}, "cve2021": {}, "cve2022": {}, "cve2023": {}, "cve2024": {},
	// Vulnerability classes
	"rce": {}, "sqli": {}, "xss": {}, "lfi": {}, "rfi": {}, "ssrf": {},
	"xxe": {}, "injection": {}, "traversal": {}, "redirect": {},
	"fileupload": {}, "deserialization": {}, "ssti": {},
	// Scan methodology
	"misconfig": {}, "misconfiguration": {}, "intrusive": {}, "safe": {},
	"vuln": {}, "vulnerability": {}, "exposure": {}, "audit": {},
	"oast": {}, "blind": {}, "fuzz": {},
	// Detection / discovery categories
	"tech": {}, "discovery": {}, "detection": {}, "favicon": {},
	"waf": {}, "osint": {}, "recon": {}, "generic": {}, "misc": {},
	// Auth categories (not tied to a specific product)
	"auth": {}, "auth-bypass": {}, "default-login": {}, "unauth": {},
	"panel": {}, "login": {}, "bruteforce": {},
	// Protocol / transport
	"http": {}, "https": {}, "network": {}, "tcp": {}, "udp": {},
	"javascript": {}, "dns": {}, "ssl": {}, "websocket": {}, "whois": {},
	"headless": {}, "code": {}, "file": {},
	// Severity levels
	"info": {}, "low": {}, "medium": {}, "high": {}, "critical": {}, "unknown": {},
	// Broad ecosystem tags
	"google": {}, "firebase": {}, "amazon": {}, "aws": {}, "azure": {},
	"packetstorm": {}, "edb": {},
	// Miscellaneous generic
	"headers": {}, "options": {}, "takeover": {},
}

func isGenericTag(tag string) bool {
	_, ok := genericTags[strings.ToLower(tag)]
	return ok
}

// hasOnlyGenericTags returns true when every tag is a generic category tag.
func hasOnlyGenericTags(tags []string) bool {
	if len(tags) == 0 {
		return true
	}
	for _, t := range tags {
		if !isGenericTag(t) {
			return false
		}
	}
	return true
}

// hasCVETag returns true when the slice contains any cve / cve20xx tag.
func hasCVETag(tags []string) bool {
	for _, t := range tags {
		tl := strings.ToLower(t)
		if tl == "cve" || strings.HasPrefix(tl, "cve20") {
			return true
		}
	}
	return false
}

// HostTechCache stores per-host technology hints.
type HostTechCache struct {
	mu    sync.RWMutex
	cache map[string]*TechHint
}

// New creates a new cache.
func New() *HostTechCache {
	return &HostTechCache{
		cache: make(map[string]*TechHint),
	}
}

// NewHostTechCache is an alias kept for callers that use the longer name.
func NewHostTechCache() *HostTechCache {
	return New()
}

// Get retrieves the cached hint for a host (nil if not present).
func (h *HostTechCache) Get(host string) (*TechHint, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	hint, exists := h.cache[host]
	return hint, exists
}

// Set stores a hint for a host.
func (h *HostTechCache) Set(host string, hint *TechHint) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cache[host] = hint
}

// HasHint returns true when a hint (any kind) exists for the host.
func (h *HostTechCache) HasHint(host string) bool {
	_, exists := h.Get(host)
	return exists
}

// ─────────────────────────────────────────────────────────────────────────────
// Probe / recording
// ─────────────────────────────────────────────────────────────────────────────

// RecordServerHeaderAndProbe records tech hints from a live HTTP response.
func (h *HostTechCache) RecordServerHeaderAndProbe(host string, resp *http.Response) {
	if _, exists := h.Get(host); exists {
		return
	}

	serverHeader := resp.Header.Get("Server")
	server, serverVersion := ParseServerHeader(serverHeader)

	baseTags := MapServerToTags(server)

	// Buffer body so DetectApplicationFromResponse can read it.
	var bodyBytes []byte
	if resp.Body != nil {
		bodyBytes, _ = io.ReadAll(io.LimitReader(resp.Body, 16384))
		resp.Body.Close()
		resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	}

	app, appTags := DetectApplicationFromResponse(resp)

	// Restore body for any downstream callers.
	if bodyBytes != nil {
		resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	}

	allTags := uniqueTags(append(baseTags, appTags...))

	tagMap := make(map[string]struct{}, len(allTags))
	for _, tag := range allTags {
		tagMap[tag] = struct{}{}
	}

	hint := &TechHint{
		Server:        server,
		ServerVersion: serverVersion,
		Application:   app,
		Tags:          tagMap,
		ExtraTags:     make(map[string]struct{}),
	}

	h.Set(host, hint)

	fmt.Printf("\n========================================\n")
	fmt.Printf("[TECH-DETECT] Host: %s\n", host)
	fmt.Printf("[TECH-DETECT] Server Header: %s\n", serverHeader)
	fmt.Printf("[TECH-DETECT] Parsed Server: %s/%s\n", server, serverVersion)
	fmt.Printf("[TECH-DETECT] Application: %s\n", app)
	fmt.Printf("[TECH-DETECT] Base Tags: %v\n", baseTags)
	fmt.Printf("[TECH-DETECT] App Tags: %v\n", appTags)
	fmt.Printf("[TECH-DETECT] All Tags: %v\n", allTags)
	fmt.Printf("========================================\n\n")
}

// RecordServerHeader records tags derived solely from the Server header.
func (h *HostTechCache) RecordServerHeader(host, serverHeader string) {
	if _, exists := h.Get(host); exists {
		return
	}

	server, version := ParseServerHeader(serverHeader)
	tags := MapServerToTags(server)

	tagMap := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		tagMap[strings.ToLower(tag)] = struct{}{}
	}

	h.Set(host, &TechHint{
		Server:        server,
		ServerVersion: version,
		Tags:          tagMap,
		ExtraTags:     make(map[string]struct{}),
	})
}

// RecordNoServerHeader marks a host that returned no Server header.
func (h *HostTechCache) RecordNoServerHeader(host string) {
	if _, exists := h.Get(host); exists {
		return
	}

	h.Set(host, &TechHint{
		Server:    "unknown",
		Tags:      make(map[string]struct{}),
		ExtraTags: make(map[string]struct{}),
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime learning
// ─────────────────────────────────────────────────────────────────────────────

// RecordTemplateMatch is called after a template executes and matches.
//
// Any product-specific tag from the template that is NOT already in Tags is
// added to ExtraTags.  ExtraTags represent technologies discovered at runtime
// that were not visible during the initial probe.  Once stored, they widen the
// allowed template set to include templates targeting those extra technologies,
// which prunes unrelated templates and speeds up the remainder of the scan.
//
// Generic / category tags (misconfig, vuln, cve, http, …) are never stored —
// only true product names carry pruning signal.
func (h *HostTechCache) RecordTemplateMatch(host string, templateTags []string) {
	hint, exists := h.Get(host)
	if !exists {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	for _, t := range templateTags {
		tl := strings.ToLower(t)
		if isGenericTag(tl) {
			continue // no product signal
		}
		if _, inPrimary := hint.Tags[tl]; inPrimary {
			continue // already known from probe
		}
		if _, inExtra := hint.ExtraTags[tl]; inExtra {
			continue // already learned
		}
		hint.ExtraTags[tl] = struct{}{}
		gologger.Debug().Msgf("[tech-filter] Host '%s': learned extra tag '%s' from template match",
			host, tl)
	}
}

// GetAllowedTags returns Tags ∪ ExtraTags as a slice for logging.
func (h *HostTechCache) GetAllowedTags(host string) []string {
	hint, exists := h.Get(host)
	if !exists {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()

	out := make([]string, 0, len(hint.Tags)+len(hint.ExtraTags))
	for t := range hint.Tags {
		out = append(out, t)
	}
	for t := range hint.ExtraTags {
		out = append(out, t)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Template filtering
// ─────────────────────────────────────────────────────────────────────────────

// ShouldSkipTemplate returns true when the template should be skipped for host.
//
// Filtering rules (in order):
//  1. No hint cached yet                          → allow (safe fallback)
//  2. Tags AND ExtraTags both empty               → allow (unknown stack)
//  3. Template has only generic/category tags     → allow (always runs)
//  4. Template has any CVE tag                    → allow (CVEs run everywhere)
//  5. Template has a product tag in Tags          → allow
//  6. Template has a product tag in ExtraTags     → allow (newly discovered tech)
//  7. Otherwise                                   → skip
func (h *HostTechCache) ShouldSkipTemplate(host string, templateTags []string, versionRanges ...map[string]interface{}) bool {
	hint, exists := h.Get(host)
	if !exists {
		return false // rule 1
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	if len(hint.Tags) == 0 && len(hint.ExtraTags) == 0 {
		return false // rule 2
	}

	if hasOnlyGenericTags(templateTags) {
		return false // rule 3
	}

	if hasCVETag(templateTags) {
		return false // rule 4
	}

	// Rules 5 & 6: check product tag overlap with Tags then ExtraTags.
	for _, t := range templateTags {
		tl := strings.ToLower(t)
		if isGenericTag(tl) {
			continue
		}
		if _, ok := hint.Tags[tl]; ok {
			return false // rule 5
		}
		if _, ok := hint.ExtraTags[tl]; ok {
			return false // rule 6
		}
	}

	return true // rule 7 — no product tag matched
}

// ShouldSkipTemplateWithVersion is a compatibility wrapper.
func (h *HostTechCache) ShouldSkipTemplateWithVersion(host string, templateTags []string, versionRanges map[string]interface{}) bool {
	return h.ShouldSkipTemplate(host, templateTags, versionRanges)
}

// ─────────────────────────────────────────────────────────────────────────────
// Accessors
// ─────────────────────────────────────────────────────────────────────────────

// GetServerHeader returns the cached Server header value.
func (h *HostTechCache) GetServerHeader(host string) string {
	hint, exists := h.Get(host)
	if !exists {
		return ""
	}
	return hint.Server
}

// GetVersion returns the cached version string.
func (h *HostTechCache) GetVersion(host string) string {
	hint, exists := h.Get(host)
	if !exists {
		return ""
	}
	return hint.ServerVersion
}

// ─────────────────────────────────────────────────────────────────────────────
// Application detection
// ─────────────────────────────────────────────────────────────────────────────

// DetectApplicationFromResponse analyzes an HTTP response for app signatures.
func DetectApplicationFromResponse(resp *http.Response) (app string, tags []string) {
	if resp == nil {
		return "", []string{}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16384))
	if err != nil {
		return "", []string{}
	}
	bodyLower := strings.ToLower(string(body))

	server := strings.ToLower(resp.Header.Get("Server"))
	xPoweredBy := strings.ToLower(resp.Header.Get("X-Powered-By"))

	if strings.Contains(bodyLower, "celery") ||
		strings.Contains(bodyLower, "flower") ||
		strings.Contains(bodyLower, "airflow") ||
		strings.Contains(resp.Request.URL.Path, "flower") {
		gologger.Debug().Msgf("[tech-detect] Detected Airflow/Flower from response")
		return "Airflow", []string{"airflow", "flower", "celery", "apache"}
	}

	if strings.Contains(bodyLower, "apache ofbiz") ||
		(strings.Contains(bodyLower, "ofbiz") && strings.Contains(bodyLower, "framework")) ||
		strings.Contains(bodyLower, "/control/main") ||
		strings.Contains(bodyLower, "ofbiz.org") {
		return "OFBiz", []string{"ofbiz", "apache", "java"}
	}

	if strings.Contains(bodyLower, "apache druid") ||
		strings.Contains(bodyLower, "druid console") ||
		strings.Contains(bodyLower, "unified-console") ||
		strings.Contains(bodyLower, "druid/coordinator") ||
		(strings.Contains(server, "jetty") && strings.Contains(bodyLower, "druid")) {
		return "Druid", []string{"druid", "apache", "java"}
	}

	if strings.Contains(bodyLower, "apache cxf") ||
		strings.Contains(bodyLower, "cxf web services") ||
		strings.Contains(bodyLower, "available soap services") ||
		(strings.Contains(bodyLower, "wsdl") && strings.Contains(bodyLower, "services")) {
		return "CXF", []string{"cxf", "apache", "soap", "webservice", "java"}
	}

	if strings.Contains(bodyLower, "apache tomcat") ||
		strings.Contains(xPoweredBy, "tomcat") ||
		strings.Contains(server, "coyote") ||
		strings.Contains(bodyLower, "tomcat/") {
		return "Tomcat", []string{"tomcat", "apache", "java"}
	}

	if strings.Contains(xPoweredBy, "servlet") ||
		strings.Contains(bodyLower, "jsessionid") {
		return "", []string{"java"}
	}

	return "", []string{}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// ParseServerHeader extracts server name and version from the Server header.
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

// MapServerToTags maps a Server header value to canonical tags.
func MapServerToTags(server string) []string {
	serverLower := strings.ToLower(server)
	var tags []string

	if strings.Contains(serverLower, "apache") || strings.Contains(serverLower, "coyote") {
		tags = append(tags, "apache")
		if strings.Contains(serverLower, "tomcat") || strings.Contains(serverLower, "coyote") {
			tags = append(tags, "tomcat", "java")
		}
	}
	if strings.Contains(serverLower, "nginx") {
		tags = append(tags, "nginx")
	}
	if strings.Contains(serverLower, "iis") || strings.Contains(serverLower, "microsoft") {
		tags = append(tags, "iis", "microsoft")
	}
	if strings.Contains(serverLower, "jetty") {
		tags = append(tags, "jetty", "java")
	}
	if strings.Contains(serverLower, "tornado") {
		tags = append(tags, "tornado", "python")
	}

	return tags
}

func uniqueTags(tags []string) []string {
	seen := make(map[string]bool, len(tags))
	result := make([]string, 0, len(tags))
	for _, tag := range tags {
		lower := strings.ToLower(tag)
		if !seen[lower] {
			seen[lower] = true
			result = append(result, lower)
		}
	}
	return result
}

// getTagList converts a tag map to a slice (used for debug logging).
func getTagList(tagMap map[string]struct{}) []string {
	tags := make([]string, 0, len(tagMap))
	for tag := range tagMap {
		tags = append(tags, tag)
	}
	return tags
}