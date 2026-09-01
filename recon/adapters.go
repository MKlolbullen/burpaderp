package recon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// RenderToolInput converts an already-normalized record into the narrowest
// stdin representation expected by common CLI tools. The ContractSocket is
// checked first, so a URL can never accidentally be fed to a domain enumerator,
// nor a hostname to a network scanner that requires explicit IP/CIDR scope.
func RenderToolInput(socket ContractSocket, record Record) (string, error) {
	validated, err := socket.Validate(DirectionInput, record)
	if err != nil {
		return "", err
	}
	switch validated.Kind {
	case KindDomain, KindHostname, KindIP, KindCIDR:
		return validated.Value + "\n", nil
	case KindService:
		host := validated.IP
		if host == "" {
			host = validated.Hostname
		}
		return net.JoinHostPort(host, strconv.Itoa(validated.Port)) + "\n", nil
	case KindHTTPTarget, KindURL, KindParameterizedURL:
		return validated.URL + "\n", nil
	default:
		return "", fmt.Errorf("no stdin renderer for %s -> %s", validated.Kind, socket.Tool.Name)
	}
}

// ParseToolOutputLine converts a single machine-readable/raw output line into
// typed records. The caller MUST pass every returned record through the output
// ContractSocket; parsing and authorization are intentionally separate layers.
func ParseToolOutputLine(toolName, line string) ([]Record, error) {
	tool := strings.ToLower(strings.TrimSpace(toolName))
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}

	switch tool {
	case "subfinder", "amass", "assetfinder", "chaos", "findomain", "puredns", "alterx", "dnsgen", "mksub":
		host, err := parseHostnameLine(line)
		if err != nil {
			return nil, err
		}
		return []Record{{Kind: KindHostname, Hostname: host, Value: host, Tool: tool, Source: tool}}, nil
	case "dnsx":
		return parseDNSX(line)
	case "naabu":
		return parseNaabu(line)
	case "httpx":
		return parseHTTPX(line)
	case "katana", "gau", "cariddi":
		u, err := parseURLLine(line)
		if err != nil {
			return nil, err
		}
		return []Record{{Kind: KindURL, URL: u, Value: u, Tool: tool, Source: tool}}, nil
	case "gf":
		return parseGF(line)
	case "nuclei":
		return parseNuclei(line)
	case "masscan":
		return nil, errors.New("masscan uses a document/array output format; use a dedicated masscan document adapter rather than treating stdout as JSONL")
	case "arjun":
		return nil, errors.New("Arjun JSON is a document keyed by target URL; use ParseArjunDocument")
	case "dalfox", "corsy", "crlfuzz":
		return nil, fmt.Errorf("%s output adapter is not declared machine-stable yet; quarantine raw output instead of guessing", tool)
	default:
		return nil, fmt.Errorf("no output adapter for tool %q", toolName)
	}
}

// ParseArjunDocument normalizes Arjun's JSON document form into one record per
// discovered parameter. It accepts either an object keyed by URL or a top-level
// object containing a URL -> parameter-list map.
func ParseArjunDocument(data []byte) ([]Record, error) {
	var root any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("parse Arjun JSON: %w", err)
	}
	obj, ok := root.(map[string]any)
	if !ok {
		return nil, errors.New("Arjun JSON root must be an object")
	}
	var out []Record
	walkArjunObject(obj, &out)
	if len(out) == 0 {
		return nil, errors.New("Arjun JSON contained no URL/parameter pairs")
	}
	return out, nil
}

func walkArjunObject(obj map[string]any, out *[]Record) {
	for key, value := range obj {
		if looksHTTPURL(key) {
			for _, param := range extractParameterNames(value) {
				*out = append(*out, Record{Kind: KindParameterizedURL, URL: key, Value: key, Parameter: param, Tool: "arjun", Source: "arjun"})
			}
			continue
		}
		if nested, ok := value.(map[string]any); ok {
			walkArjunObject(nested, out)
		}
	}
}

func extractParameterNames(value any) []string {
	seen := map[string]struct{}{}
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			p := strings.TrimSpace(x)
			if p != "" && len(p) <= 256 && !looksHTTPURL(p) {
				if _, ok := seen[p]; !ok {
					seen[p] = struct{}{}
					out = append(out, p)
				}
			}
		case []any:
			for _, item := range x {
				walk(item)
			}
		case map[string]any:
			for k, item := range x {
				lower := strings.ToLower(k)
				if lower == "params" || lower == "parameters" || lower == "get" || lower == "post" || lower == "json" || lower == "headers" {
					walk(item)
				}
			}
		}
	}
	walk(value)
	return out
}

func parseHostnameLine(line string) (string, error) {
	if strings.HasPrefix(line, "{") {
		obj, err := decodeObject(line)
		if err != nil {
			return "", err
		}
		for _, key := range []string{"host", "hostname", "domain", "name"} {
			if value := stringField(obj, key); value != "" {
				return value, nil
			}
		}
		return "", errors.New("hostname JSON output has no host/hostname/domain/name field")
	}
	return line, nil
}

func parseDNSX(line string) ([]Record, error) {
	obj, err := decodeObject(line)
	if err != nil {
		return nil, fmt.Errorf("dnsx JSONL required: %w", err)
	}
	host := firstJSONField(obj, "host", "input", "name")
	if host == "" {
		return nil, errors.New("dnsx output missing host")
	}
	addresses := append(stringSliceField(obj, "a"), stringSliceField(obj, "aaaa")...)
	cnames := append(stringSliceField(obj, "cname"), stringSliceField(obj, "cnames")...)
	if len(addresses) == 0 && len(cnames) == 0 {
		return nil, errors.New("dnsx output has no A/AAAA/CNAME records")
	}
	return []Record{{
		Kind: KindResolvedHost, Hostname: host, Value: host, Addresses: addresses, CNAMEs: cnames,
		Tool: "dnsx", Source: "dnsx",
	}}, nil
}

func parseNaabu(line string) ([]Record, error) {
	obj, err := decodeObject(line)
	if err != nil {
		return nil, fmt.Errorf("naabu JSONL required: %w", err)
	}
	port, ok := intField(obj, "port")
	if !ok {
		return nil, errors.New("naabu output missing numeric port")
	}
	ip := firstJSONField(obj, "ip")
	host := firstJSONField(obj, "host", "hostname")
	if ip == "" && host != "" {
		if net.ParseIP(host) != nil {
			ip, host = host, ""
		}
	}
	if ip == "" {
		return nil, errors.New("naabu output missing IP")
	}
	proto := firstJSONField(obj, "protocol", "proto")
	if proto == "" {
		proto = "tcp"
	}
	return []Record{{Kind: KindService, IP: ip, Hostname: host, Port: port, Protocol: proto, Tool: "naabu", Source: "naabu"}}, nil
}

func parseHTTPX(line string) ([]Record, error) {
	obj, err := decodeObject(line)
	if err != nil {
		return nil, fmt.Errorf("httpx JSONL required: %w", err)
	}
	target := firstJSONField(obj, "url", "final_url", "location")
	if target == "" {
		input := firstJSONField(obj, "input")
		if looksHTTPURL(input) {
			target = input
		}
	}
	if target == "" {
		return nil, errors.New("httpx output missing URL")
	}
	status, _ := intField(obj, "status_code", "status-code", "status")
	return []Record{{Kind: KindHTTPTarget, URL: target, Value: target, Status: status, Tool: "httpx", Source: "httpx"}}, nil
}

func parseURLLine(line string) (string, error) {
	if !strings.HasPrefix(line, "{") {
		if !looksHTTPURL(line) {
			return "", errors.New("tool output is not an HTTP(S) URL")
		}
		return line, nil
	}
	obj, err := decodeObject(line)
	if err != nil {
		return "", err
	}
	for _, path := range [][]string{{"url"}, {"endpoint"}, {"request", "endpoint"}, {"request", "url"}} {
		if value := nestedString(obj, path...); looksHTTPURL(value) {
			return value, nil
		}
	}
	return "", errors.New("crawler JSON output has no HTTP(S) URL/endpoint")
}

func parseGF(line string) ([]Record, error) {
	if strings.HasPrefix(line, "{") {
		obj, err := decodeObject(line)
		if err != nil {
			return nil, err
		}
		line = firstJSONField(obj, "url", "value")
	}
	u, err := url.Parse(line)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("gf output is not an HTTP(S) URL")
	}
	params := u.Query()
	if len(params) == 0 {
		return nil, errors.New("gf URL has no query parameters")
	}
	out := make([]Record, 0, len(params))
	for name := range params {
		out = append(out, Record{Kind: KindParameterizedURL, URL: line, Value: line, Parameter: name, Tool: "gf", Source: "gf"})
	}
	return out, nil
}

func parseNuclei(line string) ([]Record, error) {
	obj, err := decodeObject(line)
	if err != nil {
		return nil, fmt.Errorf("nuclei JSONL required: %w", err)
	}
	target := firstJSONField(obj, "matched-at", "matched_at", "url", "host")
	if target == "" {
		return nil, errors.New("nuclei output missing matched target")
	}
	severity := "info"
	if info, ok := obj["info"].(map[string]any); ok {
		if value := stringField(info, "severity"); value != "" {
			severity = value
		}
	}
	templateID := firstJSONField(obj, "template-id", "template_id")
	matcher := firstJSONField(obj, "matcher-name", "matcher_name", "type")
	evidenceParts := make([]string, 0, 4)
	if templateID != "" {
		evidenceParts = append(evidenceParts, "template="+templateID)
	}
	if matcher != "" {
		evidenceParts = append(evidenceParts, "matcher="+matcher)
	}
	if request := stringField(obj, "request"); request != "" {
		evidenceParts = append(evidenceParts, "request="+boundedEvidence(request, 8192))
	}
	if response := stringField(obj, "response"); response != "" {
		evidenceParts = append(evidenceParts, "response="+boundedEvidence(response, 8192))
	}
	return []Record{{
		Kind: KindFinding, Value: target, URL: target, Tool: "nuclei", Severity: severity,
		Evidence: strings.Join(evidenceParts, "\n"), Source: templateID,
	}}, nil
}

func decodeObject(line string) (map[string]any, error) {
	var obj map[string]any
	dec := json.NewDecoder(strings.NewReader(line))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, errors.New("JSON object is null")
	}
	return obj, nil
}

func stringField(obj map[string]any, key string) string {
	value, ok := obj[key]
	if !ok || value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return ""
	}
}

func firstJSONField(obj map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := stringField(obj, key); value != "" {
			return value
		}
	}
	return ""
}

func stringSliceField(obj map[string]any, key string) []string {
	value, ok := obj[key]
	if !ok || value == nil {
		return nil
	}
	switch v := value.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []string{strings.TrimSpace(v)}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	default:
		return nil
	}
}

func intField(obj map[string]any, keys ...string) (int, bool) {
	for _, key := range keys {
		value, ok := obj[key]
		if !ok {
			continue
		}
		switch v := value.(type) {
		case json.Number:
			i, err := strconv.Atoi(v.String())
			if err == nil {
				return i, true
			}
		case float64:
			return int(v), true
		case string:
			i, err := strconv.Atoi(strings.TrimSpace(v))
			if err == nil {
				return i, true
			}
		}
	}
	return 0, false
}

func nestedString(obj map[string]any, path ...string) string {
	var current any = obj
	for i, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		value, ok := m[key]
		if !ok {
			return ""
		}
		if i == len(path)-1 {
			if s, ok := value.(string); ok {
				return strings.TrimSpace(s)
			}
			return ""
		}
		current = value
	}
	return ""
}

func looksHTTPURL(value string) bool {
	u, err := url.Parse(strings.TrimSpace(value))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func boundedEvidence(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "…[truncated]"
}
