package recon

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"strings"
)

var runIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ResolveRunID returns a canonical caller-supplied UUID or creates a cryptographically random
// UUIDv4. Every reconctl run therefore has an identifier that can cross the Go JSONL -> Burp import
// boundary without relying on a timestamp or filename convention.
func ResolveRunID(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value != "" {
		if !runIDPattern.MatchString(value) {
			return "", fmt.Errorf("run ID must be a canonical UUID")
		}
		return value, nil
	}
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("generate run ID: %w", err)
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16]), nil
}

// StampRunID copies records and attaches the execution run identifier. Output records are produced
// by this execution, so their RunID is always overwritten rather than inheriting an upstream stage's
// identifier.
func StampRunID(records []Record, runID string) []Record {
	stamped := make([]Record, len(records))
	copy(stamped, records)
	for i := range stamped {
		stamped[i].RunID = runID
	}
	return stamped
}
