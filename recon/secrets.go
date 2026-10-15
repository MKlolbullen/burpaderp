package recon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// This file holds the output-normalization boundary for the secret-scanning
// tools (gitleaks, trufflehog, and — once their report/source bridges are wired
// — postleaks/scan4secrets). As elsewhere in the sidecar, parsing is kept
// strictly separate from execution and scope authorization: these functions turn
// a tool's machine-readable report into typed `finding` records, and the output
// ContractSocket still has the final say on whether a record may leave the tool.
//
// The *source* these tools consume (a git repository, a filesystem tree, a
// Postman export folder) is intentionally not modeled as a pipeline Kind yet, so
// no executable CommandProfile is declared for them. The adapters below are still
// useful on their own: a Java/Montoya bridge (or `reconctl adapt`) can feed a
// gitleaks/trufflehog report through them to import findings into the same typed
// stream every other stage produces.

// ParseGitleaksReport normalizes a gitleaks JSON report into bounded findings.
// Gitleaks emits a single top-level JSON array of finding objects (the
// `--report-format json` form), not JSONL, so — like Arjun's document form — it
// is parsed as a whole document rather than line by line.
func ParseGitleaksReport(data []byte) ([]Record, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil
	}
	var entries []map[string]any
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&entries); err != nil {
		return nil, fmt.Errorf("parse gitleaks JSON report: %w", err)
	}
	out := make([]Record, 0, len(entries))
	for _, entry := range entries {
		record, err := gitleaksFinding(entry)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}

func gitleaksFinding(obj map[string]any) (Record, error) {
	rule := firstJSONField(obj, "RuleID", "ruleID", "rule_id")
	file := firstJSONField(obj, "File", "file")
	fingerprint := firstJSONField(obj, "Fingerprint", "fingerprint")
	commit := firstJSONField(obj, "Commit", "commit")
	description := firstJSONField(obj, "Description", "description")
	match := firstJSONField(obj, "Match", "match")
	startLine, _ := intField(obj, "StartLine", "startLine", "start_line")

	location := file
	if location != "" && startLine > 0 {
		location = file + ":" + strconv.Itoa(startLine)
	}

	value := firstNonBlank(location, fingerprint, commit, rule)
	if value == "" {
		return Record{}, errors.New("gitleaks finding has no File/Fingerprint/Commit/RuleID to anchor on")
	}

	evidence := make([]string, 0, 5)
	if rule != "" {
		evidence = append(evidence, "rule="+rule)
	}
	if description != "" {
		evidence = append(evidence, "description="+description)
	}
	if location != "" {
		evidence = append(evidence, "location="+location)
	}
	if commit != "" {
		evidence = append(evidence, "commit="+commit)
	}
	if match != "" {
		evidence = append(evidence, "match="+boundedEvidence(match, 2048))
	}

	return Record{
		Kind: KindFinding, Value: value, Tool: "gitleaks", Severity: "high",
		Evidence: strings.Join(evidence, "\n"), Source: firstNonBlank(rule, fingerprint),
	}, nil
}

// parseTrufflehog normalizes a single line of trufflehog v3 `--json` output (one
// JSON object per secret) into a bounded finding. Verified secrets are escalated
// to `high`; unverified candidates stay `medium`. The anchor value is the most
// specific source locator trufflehog carries for that finding.
func parseTrufflehog(line string) ([]Record, error) {
	obj, err := decodeObject(line)
	if err != nil {
		return nil, fmt.Errorf("trufflehog JSONL required: %w", err)
	}
	detector := firstJSONField(obj, "DetectorName", "detector_name")
	decoder := firstJSONField(obj, "DecoderName", "decoder_name")
	sourceName := firstJSONField(obj, "SourceName", "source_name")
	redacted := firstJSONField(obj, "Redacted", "redacted")
	verified := boolField(obj, "Verified", "verified")

	location := trufflehogLocation(obj)
	value := firstNonBlank(location, sourceName, redacted, detector)
	if value == "" {
		return nil, errors.New("trufflehog output has no source metadata/detector to anchor on")
	}

	severity := "medium"
	if verified {
		severity = "high"
	}

	evidence := make([]string, 0, 6)
	if detector != "" {
		evidence = append(evidence, "detector="+detector)
	}
	if decoder != "" {
		evidence = append(evidence, "decoder="+decoder)
	}
	evidence = append(evidence, "verified="+strconv.FormatBool(verified))
	if sourceName != "" {
		evidence = append(evidence, "source="+sourceName)
	}
	if location != "" {
		evidence = append(evidence, "location="+location)
	}
	if redacted != "" {
		evidence = append(evidence, "redacted="+boundedEvidence(redacted, 512))
	}

	return []Record{{
		Kind: KindFinding, Value: value, Tool: "trufflehog", Severity: severity,
		Evidence: strings.Join(evidence, "\n"), Source: firstNonBlank(detector, sourceName),
	}}, nil
}

// trufflehogLocation digs the most specific locator out of SourceMetadata.Data.
// Data is keyed by source type (Git, Github, Filesystem, S3, …); each nested
// object carries a subset of link/repository/file/commit/line.
func trufflehogLocation(obj map[string]any) string {
	meta, ok := obj["SourceMetadata"].(map[string]any)
	if !ok {
		return ""
	}
	data, ok := meta["Data"].(map[string]any)
	if !ok {
		return ""
	}
	for _, raw := range data {
		src, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		link := firstJSONField(src, "link")
		repository := firstJSONField(src, "repository")
		file := firstJSONField(src, "file")
		commit := firstJSONField(src, "commit")
		lineNo, _ := intField(src, "line")

		switch {
		case link != "":
			return link
		case repository != "" && file != "":
			loc := repository + "#" + file
			if lineNo > 0 {
				loc += ":" + strconv.Itoa(lineNo)
			}
			return loc
		case file != "":
			if lineNo > 0 {
				return file + ":" + strconv.Itoa(lineNo)
			}
			return file
		case repository != "":
			return repository
		case commit != "":
			return commit
		}
	}
	return ""
}

func boolField(obj map[string]any, keys ...string) bool {
	for _, key := range keys {
		value, ok := obj[key]
		if !ok || value == nil {
			continue
		}
		switch v := value.(type) {
		case bool:
			return v
		case string:
			if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
				return b
			}
		}
	}
	return false
}
