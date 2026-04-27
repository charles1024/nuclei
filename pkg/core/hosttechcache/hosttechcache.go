package hosttechcache

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
)

// TechHint represents detected technology on a host
type TechHint struct {
	Server        string              // "Apache-Coyote/1.1", "TornadoServer/6.0.3"
	ServerVersion string              // "1.1", "6.0.3"
	Framework     string              // "Tomcat", "Tornado"
	Application   string              // "Airflow", "OFBiz", "Druid", "CFX"
	AppVersion    string              // "1.10.10"
	Tags          map[string]struct{} // Required tags for filtering
}

// HostTechCache stores per-host technology hints
type HostTechCache struct {
	mu    sync.RWMutex
	cache map[string]*TechHint
}

// New creates a new cache
func New() *HostTechCache {
	return &HostTechCache{
		cache: make(map[string]*TechHint),
	}
}

// NewHostTechCache alias
func NewHostTechCache() *HostTechCache {
	return New()
}

// Get retrieves cached hint
func (h *HostTechCache) Get(host string) (*TechHint, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	hint, exists := h.cache[host]
	return hint, exists
}

// Set stores a hint
func (h *HostTechCache) Set(host string, hint *TechHint) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cache[host] = hint
}

// HasHint checks if cached
func (h *HostTechCache) HasHint(host string) bool {
	_, exists := h.Get(host)
	return exists
}

// ParseServerHeader extracts server and version
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

// RecordServerHeaderAndProbe records tech hints from a live HTTP response
func (h *HostTechCache) RecordServerHeaderAndProbe(host string, resp *http.Response) {
	if _, exists := h.Get(host); exists {
		return
	}

	serverHeader := resp.Header.Get("Server")
	server, serverVersion := ParseServerHeader(serverHeader)

	baseTags := MapServerToTags(server)

	// Save body bytes so DetectApplicationFromResponse can read it
	// (body may already be partially or fully read upstream)
	var bodyBytes []byte
	if resp.Body != nil {
		bodyBytes, _ = io.ReadAll(io.LimitReader(resp.Body, 16384))
		resp.Body.Close()
		resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	}

	app, appTags := DetectApplicationFromResponse(resp)

	// Restore body for any downstream callers
	if bodyBytes != nil {
		resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	}

	// Combine tags
	allTags := append(baseTags, appTags...)
	allTags = uniqueTags(allTags)

	// Convert to map for fast lookup
	tagMap := make(map[string]struct{})
	for _, tag := range allTags {
		tagMap[tag] = struct{}{}
	}

	hint := &TechHint{
		Server:        server,
		ServerVersion: serverVersion,
		Application:   app,
		Tags:          tagMap,
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

// DetectApplicationFromResponse analyzes HTTP response for app signatures
func DetectApplicationFromResponse(resp *http.Response) (app string, tags []string) {
	if resp == nil {
		return "", []string{}
	}

	// Read first 16KB of response body
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16384))
	if err != nil {
		return "", []string{}
	}
	bodyLower := strings.ToLower(string(body))

	// Check headers
	server := strings.ToLower(resp.Header.Get("Server"))
	xPoweredBy := strings.ToLower(resp.Header.Get("X-Powered-By"))

	// Airflow/Flower detection
	if strings.Contains(bodyLower, "celery") ||
		strings.Contains(bodyLower, "flower") ||
		strings.Contains(bodyLower, "airflow") ||
		strings.Contains(resp.Request.URL.Path, "flower") {
		gologger.Debug().Msgf("[tech-detect] Detected Airflow/Flower from response")
		return "Airflow", []string{"airflow", "flower", "celery", "apache"}
	}

	// OFBiz detection
	if strings.Contains(bodyLower, "apache ofbiz") ||
		strings.Contains(bodyLower, "ofbiz") && strings.Contains(bodyLower, "framework") ||
		strings.Contains(bodyLower, "/control/main") ||
		strings.Contains(bodyLower, "ofbiz.org") {
		return "OFBiz", []string{"ofbiz", "apache", "java"}
	}

	// Druid detection
	if strings.Contains(bodyLower, "apache druid") ||
		strings.Contains(bodyLower, "druid console") ||
		strings.Contains(bodyLower, "unified-console") ||
		strings.Contains(bodyLower, "druid/coordinator") ||
		strings.Contains(server, "jetty") && strings.Contains(bodyLower, "druid") {
		return "Druid", []string{"druid", "apache", "java"}
	}

	// CXF detection
	if strings.Contains(bodyLower, "apache cxf") ||
		strings.Contains(bodyLower, "cxf web services") ||
		strings.Contains(bodyLower, "available soap services") ||
		(strings.Contains(bodyLower, "wsdl") && strings.Contains(bodyLower, "services")) {
		return "CXF", []string{"cxf", "apache", "soap", "webservice", "java"}
	}

	// Tomcat detection
	if strings.Contains(bodyLower, "apache tomcat") ||
		strings.Contains(xPoweredBy, "tomcat") ||
		strings.Contains(server, "coyote") ||
		strings.Contains(bodyLower, "tomcat/") {
		return "Tomcat", []string{"tomcat", "apache", "java"}
	}

	// Generic Java detection
	if strings.Contains(xPoweredBy, "servlet") ||
		strings.Contains(bodyLower, "jsessionid") {
		return "", []string{"java"}
	}

	return "", []string{}
}

// MapServerToTags maps server header to base tags
func MapServerToTags(server string) []string {
	serverLower := strings.ToLower(server)
	tags := []string{}

	if strings.Contains(serverLower, "apache") ||
		strings.Contains(serverLower, "coyote") {
		tags = append(tags, "apache")
		if strings.Contains(serverLower, "tomcat") ||
			strings.Contains(serverLower, "coyote") {
			tags = append(tags, "tomcat", "java")
		}
	}

	if strings.Contains(serverLower, "nginx") {
		tags = append(tags, "nginx")
	}

	if strings.Contains(serverLower, "iis") ||
		strings.Contains(serverLower, "microsoft") {
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
	seen := make(map[string]bool)
	result := []string{}
	for _, tag := range tags {
		lower := strings.ToLower(tag)
		if !seen[lower] {
			seen[lower] = true
			result = append(result, lower)
		}
	}
	return result
}

// RecordServerHeader - simple version without probe
func (h *HostTechCache) RecordServerHeader(host string, serverHeader string) {
	if _, exists := h.Get(host); exists {
		return
	}

	server, version := ParseServerHeader(serverHeader)
	tags := MapServerToTags(server)

	tagMap := make(map[string]struct{})
	for _, tag := range tags {
		tagMap[strings.ToLower(tag)] = struct{}{}
	}

	h.Set(host, &TechHint{
		Server:        server,
		ServerVersion: version,
		Tags:          tagMap,
	})
}

// RecordNoServerHeader marks host with no server header
func (h *HostTechCache) RecordNoServerHeader(host string) {
	if _, exists := h.Get(host); exists {
		return
	}

	h.Set(host, &TechHint{
		Server: "unknown",
		Tags:   make(map[string]struct{}),
	})
}

func (h *HostTechCache) ShouldSkipTemplate(host string, templateTags []string, versionRanges ...map[string]interface{}) bool {
	hint, exists := h.Get(host)
	if !exists {
		return false
	}

	if len(hint.Tags) == 0 {
		return false
	}

	// Always allow templates with no tech-specific tags (generic/info templates)
	if len(templateTags) == 0 {
		return false
	}
/*
	fmt.Printf("\n[FILTER] Checking template against host '%s'\n", host)
	fmt.Printf("[FILTER] Host tags: %v\n", getTagList(hint.Tags))
	fmt.Printf("[FILTER] Template tags: %v\n", templateTags)
	*/

	for _, templateTag := range templateTags {
		templateTagLower := strings.ToLower(templateTag)
		if _, found := hint.Tags[templateTagLower]; found {
		
			//fmt.Printf("[FILTER] ✓ MATCH: '%s' -> ALLOW\n", templateTag)
			return false
		}
	}
/*
	fmt.Printf("[FILTER] ✗ NO MATCH -> SKIP\n")
*/
	return true
}

// getTagList converts tag map to slice for debugging
func getTagList(tagMap map[string]struct{}) []string {
	tags := []string{}
	for tag := range tagMap {
		tags = append(tags, tag)
	}
	return tags
}

// ShouldSkipTemplateWithVersion (3-arg compatibility)
func (h *HostTechCache) ShouldSkipTemplateWithVersion(host string, templateTags []string, versionRanges map[string]interface{}) bool {
	return h.ShouldSkipTemplate(host, templateTags, versionRanges)
}

// GetServerHeader returns server header
func (h *HostTechCache) GetServerHeader(host string) string {
	hint, exists := h.Get(host)
	if !exists {
		return ""
	}
	return hint.Server
}

// GetVersion returns version
func (h *HostTechCache) GetVersion(host string) string {
	hint, exists := h.Get(host)
	if !exists {
		return ""
	}
	return hint.ServerVersion
}

// RecordTemplateMatch placeholder
func (h *HostTechCache) RecordTemplateMatch(host string, templateID string) {
	// Optional
}