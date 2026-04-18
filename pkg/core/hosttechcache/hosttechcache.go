package hosttechcache

import (
	"fmt"
	"strings"
	"sync"
	"github.com/projectdiscovery/gologger"
)

// TechHint represents a detected technology on a host that can be used
// to filter templates before execution.
type TechHint struct {
	// ServerHeader stores the original Server header value for logging purposes
	ServerHeader string
	Version		string
	// Tags is the set of template tags that are REQUIRED for this host.
	// A template is skipped unless it contains at least one of these tags,
	// or the set is empty (meaning: no filtering).
	Tags map[string]struct{}
}

// HostTechCache stores per-host technology hints derived from early HTTP
// responses (e.g. the Server: header).  It is safe for concurrent use.
type HostTechCache struct {
	mu    sync.RWMutex
	hints map[string]*TechHint // keyed by normalised host (scheme+host)
}

// NewHostTechCache returns an initialised HostTechCache.
func NewHostTechCache() *HostTechCache {
	return &HostTechCache{hints: make(map[string]*TechHint)}
}

// RecordServerHeader inspects a raw Server header value and, if it contains
// a known technology keyword, records a tag requirement for that host.
//
// Currently understood keywords → required tag:
//
//	"apache" → "apache"
//
// The mapping is intentionally simple and lowercase-compared so that
// "Apache/2.4.51 (Unix)" and "apache" both resolve to the same hint.
func (c *HostTechCache) RecordServerHeader(host, serverHeader string) {
	lower := strings.ToLower(serverHeader)

	var requiredTags []string
	var detectedVersion string
	
	// Detect different server types
	if strings.Contains(lower, "apache") {
		requiredTags = append(requiredTags, "apache")
		detectedVersion = extractVersion(serverHeader)
	}
	/*
	} else if strings.Contains(lower, "nginx") {
		requiredTags = append(requiredTags, "nginx")
		detectedVersion = extractVersion(serverHeader)
	} else if strings.Contains(lower, "iis") || strings.Contains(lower, "microsoft") {
		requiredTags = append(requiredTags, "iis", "microsoft")
		detectedVersion = extractVersion(serverHeader)
	} else if strings.Contains(lower, "tomcat") {
		requiredTags = append(requiredTags, "apache", "tomcat")
		detectedVersion = extractVersion(serverHeader)
	} else if strings.Contains(lower, "jetty") {
		requiredTags = append(requiredTags, "jetty")
		detectedVersion = extractVersion(serverHeader)
	} else if strings.Contains(lower, "websphere") {
		requiredTags = append(requiredTags, "websphere", "ibm")
		detectedVersion = extractVersion(serverHeader)
	} else if strings.Contains(lower, "weblogic") {
		requiredTags = append(requiredTags, "weblogic", "oracle")
		detectedVersion = extractVersion(serverHeader)
	}
	*/
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(requiredTags) == 0 {
		// Unknown server - record but don't filter
		c.hints[host] = &TechHint{
			ServerHeader: serverHeader,
			Version:      detectedVersion,
			Tags:         make(map[string]struct{}),
		}
		gologger.Debug().Msgf("[tech-filter] RECORDED hint for host '%s' — Server: '%s' → UNKNOWN server type, will allow all templates",
			host, serverHeader)
		return
	}

	gologger.Debug().Msgf("[tech-filter] RECORDED hint for host '%s' — Server: '%s', Version: '%s' → required tags: %v",
		host, serverHeader, detectedVersion, requiredTags)

	hint := &TechHint{
		ServerHeader: serverHeader,
		Version:      detectedVersion,
		Tags:         make(map[string]struct{}, len(requiredTags)),
	}
	for _, t := range requiredTags {
		hint.Tags[t] = struct{}{}
	}
	c.hints[host] = hint
}

// extractVersion extracts version number from Server header
func extractVersion(serverHeader string) string {
	// Examples to handle:
	// "Apache/2.4.41 (Unix)" -> "2.4.41"
	// "Apache-Coyote/1.1" -> "1.1"
	// "Apache Tomcat/8.0.43" -> "8.0.43"
	
	parts := strings.Split(serverHeader, "/")
	if len(parts) >= 2 {
		version := strings.Split(parts[1], " ")[0] // Remove trailing info
		version = strings.TrimSpace(version)
		return version
	}
	return ""
}

// GetVersion returns the detected version for a host
func (c *HostTechCache) GetVersion(host string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	hint, exists := c.hints[host]
	if !exists || hint == nil {
		return ""
	}
	return hint.Version
}

// ShouldSkipTemplate returns true when the cache has a hint for the given host
// AND the template's tags contain none of the required tags.
// This is the simpler version without version checking (for backward compatibility)
func (c *HostTechCache) ShouldSkipTemplate(host string, templateTags []string) bool {
	c.mu.RLock()
	hint, ok := c.hints[host]
	c.mu.RUnlock()

	if !ok || len(hint.Tags) == 0 {
		return false // no information → don't skip
	}

	for _, tag := range templateTags {
		if _, required := hint.Tags[strings.ToLower(tag)]; required {
			return false // template has at least one matching tag → keep it
		}
	}
	return true // no matching tag found → skip
}

// ShouldSkipTemplateWithVersion checks both tags AND version ranges
func (c *HostTechCache) ShouldSkipTemplateWithVersion(host string, templateTags []string, versionRanges map[string]interface{}) bool {
	c.mu.RLock()
	hint, ok := c.hints[host]
	c.mu.RUnlock()

	if !ok || len(hint.Tags) == 0 {
		return false // no information → don't skip
	}

	// First check tags
	hasMatchingTag := false
	for _, tag := range templateTags {
		if _, required := hint.Tags[strings.ToLower(tag)]; required {
			hasMatchingTag = true
			break
		}
	}
	
	if !hasMatchingTag {
		return true // no matching tag → skip
	}

	// If tags match, check version ranges
	if len(versionRanges) > 0 && hint.Version != "" {
		if !versionMatches(hint.Version, versionRanges) {
			return true // version doesn't match → skip
		}
	}

	return false // tag matches and (no version check OR version matches) → don't skip
}

// versionMatches checks if detected version matches the template's version ranges
func versionMatches(detectedVersion string, versionRanges map[string]interface{}) bool {
	for rangeType, rangeValue := range versionRanges {
		switch rangeType {
		case "equals":
			// Handle both single string and array of strings
			if strVal, ok := rangeValue.(string); ok {
				// Single version: "2.0.0"
				if detectedVersion == strVal {
					return true
				}
			} else if arrVal, ok := rangeValue.([]interface{}); ok {
				// Array of versions: ["2.0.0", "2.1.0", "2.2.0"]
				for _, item := range arrVal {
					if strItem, ok := item.(string); ok {
						if detectedVersion == strItem {
							return true
						}
					}
				}
			}
			
		case "less_than":
			// Handle both single string and array of strings
			if strVal, ok := rangeValue.(string); ok {
				// Single threshold: "9.0.0"
				if compareVersions(detectedVersion, strVal) < 0 {
					return true
				}
			} else if arrVal, ok := rangeValue.([]interface{}); ok {
				// Array of thresholds: ["9.0.0", "10.0.0"]
				// Version matches if it's less than ANY of the thresholds
				for _, item := range arrVal {
					if strItem, ok := item.(string); ok {
						if compareVersions(detectedVersion, strItem) < 0 {
							return true
						}
					}
				}
			}
			
		case "between-inclusive":
			// Handle both single string and array of strings
			if strVal, ok := rangeValue.(string); ok {
				// Single range: "2.0.0,2.3.33"
				if matchesBetweenInclusive(detectedVersion, strVal) {
					return true
				}
			} else if arrVal, ok := rangeValue.([]interface{}); ok {
				// Array of ranges: ["2.0.0,2.3.33", "2.5,2.5.10.1"]
				for _, item := range arrVal {
					if strItem, ok := item.(string); ok {
						if matchesBetweenInclusive(detectedVersion, strItem) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// matchesBetweenInclusive checks if version is between min and max (inclusive)
func matchesBetweenInclusive(version, rangeStr string) bool {
	parts := strings.Split(rangeStr, ",")
	if len(parts) != 2 {
		return false
	}
	
	minVersion := strings.TrimSpace(parts[0])
	maxVersion := strings.TrimSpace(parts[1])
	
	// version >= minVersion AND version <= maxVersion
	return compareVersions(version, minVersion) >= 0 && compareVersions(version, maxVersion) <= 0
}

// compareVersions compares two version strings
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func compareVersions(v1, v2 string) int {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")
	
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}
	
	for i := 0; i < maxLen; i++ {
		var p1, p2 int
		
		if i < len(parts1) {
			fmt.Sscanf(parts1[i], "%d", &p1)
		}
		if i < len(parts2) {
			fmt.Sscanf(parts2[i], "%d", &p2)
		}
		
		if p1 < p2 {
			return -1
		} else if p1 > p2 {
			return 1
		}
	}
	
	return 0
}

// HasHint returns true if any hint (including "no recognised tech") has been
// recorded for this host, so we don't probe the same host twice.
func (c *HostTechCache) HasHint(host string) bool {
	c.mu.RLock()
	_, ok := c.hints[host]
	c.mu.RUnlock()
	return ok
}


// RecordNoServerHeader marks that we checked a host but found no Server header
func (c *HostTechCache) RecordNoServerHeader(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Create an empty TechHint to indicate we checked but found nothing
	c.hints[host] = &TechHint{
		ServerHeader: "",
		Tags:         make(map[string]struct{}),
	}
	gologger.Debug().Msgf("[tech-filter] RECORDED no Server header for host '%s'", host)
}

// GetServerHeader returns the detected server header for a host
func (c *HostTechCache) GetServerHeader(host string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	hint, exists := c.hints[host]
	if !exists || hint == nil {
		return ""
	}
	return hint.ServerHeader
}

// RecordTemplateMatch updates the cache when a template matches
// This allows learning what technologies are present from successful detections
func (c *HostTechCache) RecordTemplateMatch(host string, templateTags []string) {
	if len(templateTags) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	hint, exists := c.hints[host]
	if !exists {
		// Create new hint from template match
		hint = &TechHint{
			ServerHeader: "",
			Version:      "",
			Tags:         make(map[string]struct{}),
		}
		c.hints[host] = hint
	}

	// Add all template tags to the hint
	added := []string{}
	for _, tag := range templateTags {
		tag = strings.ToLower(tag)
		if _, exists := hint.Tags[tag]; !exists {
			hint.Tags[tag] = struct{}{}
			added = append(added, tag)
		}
	}

	if len(added) > 0 {
		gologger.Debug().Msgf("[tech-filter] LEARNED from template match on host '%s' → added tags: %v", 
			host, added)
	}
}
