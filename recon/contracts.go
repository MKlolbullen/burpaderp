package recon

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Kind is the schema carried between pipeline stages. A tool may only receive
// kinds listed in its contract and may only emit kinds declared by that same
// contract.
type Kind string

const (
	KindDomain           Kind = "domain"
	KindHostname         Kind = "hostname"
	KindResolvedHost     Kind = "resolved_host"
	KindIP               Kind = "ip"
	KindCIDR             Kind = "cidr"
	KindService          Kind = "service"
	KindHTTPTarget       Kind = "http_target"
	KindURL              Kind = "url"
	KindParameterizedURL Kind = "parameterized_url"
	KindPayload          Kind = "payload"
	KindFinding          Kind = "finding"
)

// Record is the JSONL wire type used by the Go recon sidecar. It is deliberately
// a tagged union rather than a map[string]any: every boundary can validate the
// fields required by record.Kind before a value reaches another tool.
type Record struct {
	Kind          Kind      `json:"kind"`
	Value         string    `json:"value,omitempty"`
	Hostname      string    `json:"hostname,omitempty"`
	Addresses     []string  `json:"addresses,omitempty"`
	CNAMEs        []string  `json:"cnames,omitempty"`
	IP            string    `json:"ip,omitempty"`
	CIDR          string    `json:"cidr,omitempty"`
	Port          int       `json:"port,omitempty"`
	Protocol      string    `json:"protocol,omitempty"`
	URL           string    `json:"url,omitempty"`
	Status        int       `json:"status,omitempty"`
	Parameter     string    `json:"parameter,omitempty"`
	PayloadFamily string    `json:"payload_family,omitempty"`
	Tool          string    `json:"tool,omitempty"`
	Severity      string    `json:"severity,omitempty"`
	Evidence      string    `json:"evidence,omitempty"`
	Source        string    `json:"source,omitempty"`
	RunID         string    `json:"run_id,omitempty"`
	CreatedAt     time.Time `json:"created_at,omitempty"`

	// Derived marks an IP/service that came from resolving an in-scope hostname
	// rather than from an explicitly authorised IP/CIDR. Network-probe stages do
	// not accept such records unless AllowDerivedIPs is explicitly enabled.
	Derived bool `json:"derived,omitempty"`
}

// RejectedRecord is the quarantine format. Bad tool output is data, not a log
// line: preserve it with the exact boundary, source and reason so the run can be
// audited and adapters can be fixed without silently losing evidence.
type RejectedRecord struct {
	Tool      string    `json:"tool,omitempty"`
	Direction string    `json:"direction"`
	Reason    string    `json:"reason"`
	Raw       string    `json:"raw,omitempty"`
	Record    *Record   `json:"record,omitempty"`
	Source    string    `json:"source,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Scope is intentionally conservative for network probing. Domain scope allows
// DNS and HTTP work against the hostname, but does not automatically authorise
// port scanning every IP the hostname resolves to (CDNs/shared hosting make that
// assumption unsafe). Explicit CIDRs/IPs are accepted; derived IPs require the
// dedicated opt-in.
type Scope struct {
	domains         []string
	cidrs           []netip.Prefix
	allowDerivedIPs bool
}

func NewScope(domains, cidrs []string, allowDerivedIPs bool) (Scope, error) {
	s := Scope{allowDerivedIPs: allowDerivedIPs}
	seenDomains := map[string]struct{}{}
	for _, raw := range domains {
		d, err := NormalizeFQDN(raw)
		if err != nil {
			return Scope{}, fmt.Errorf("scope domain %q: %w", raw, err)
		}
		if _, ok := seenDomains[d]; !ok {
			seenDomains[d] = struct{}{}
			s.domains = append(s.domains, d)
		}
	}
	seenCIDRs := map[string]struct{}{}
	for _, raw := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return Scope{}, fmt.Errorf("scope CIDR %q: %w", raw, err)
		}
		p = p.Masked()
		key := p.String()
		if _, ok := seenCIDRs[key]; !ok {
			seenCIDRs[key] = struct{}{}
			s.cidrs = append(s.cidrs, p)
		}
	}
	if len(s.domains) == 0 && len(s.cidrs) == 0 {
		return Scope{}, errors.New("scope must contain at least one domain or CIDR")
	}
	return s, nil
}

func (s Scope) Domains() []string { return append([]string(nil), s.domains...) }
func (s Scope) CIDRs() []netip.Prefix { return append([]netip.Prefix(nil), s.cidrs...) }
func (s Scope) AllowDerivedIPs() bool { return s.allowDerivedIPs }

func (s Scope) InScopeHostname(raw string) bool {
	host, err := NormalizeFQDN(raw)
	if err != nil {
		return false
	}
	for _, root := range s.domains {
		if host == root || strings.HasSuffix(host, "."+root) {
			return true
		}
	}
	return false
}

func (s Scope) InScopeIP(raw string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range s.cidrs {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (s Scope) InScopePrefix(raw string) bool {
	p, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	p = p.Masked()
	for _, allowed := range s.cidrs {
		if allowed.Bits() <= p.Bits() && allowed.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func (s Scope) InScopeURL(raw string) bool {
	canonical, err := NormalizeHTTPURL(raw)
	if err != nil {
		return false
	}
	u, _ := url.Parse(canonical)
	h := u.Hostname()
	if addr, err := netip.ParseAddr(h); err == nil {
		return s.InScopeIP(addr.Unmap().String())
	}
	return s.InScopeHostname(h)
}

// Validate normalises a record and enforces the scope rules relevant to its
// kind. The returned record is canonical and suitable for hashing/deduplication.
func (s Scope) Validate(r Record) (Record, error) {
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}

	switch r.Kind {
	case KindDomain:
		v := firstNonBlank(r.Value, r.Hostname)
		d, err := NormalizeFQDN(v)
		if err != nil {
			return Record{}, err
		}
		if !s.InScopeHostname(d) {
			return Record{}, fmt.Errorf("domain %q is outside scope", d)
		}
		r.Value, r.Hostname = d, d

	case KindHostname:
		v := firstNonBlank(r.Hostname, r.Value)
		h, err := NormalizeFQDN(v)
		if err != nil {
			return Record{}, err
		}
		if !s.InScopeHostname(h) {
			return Record{}, fmt.Errorf("hostname %q is outside scope", h)
		}
		r.Value, r.Hostname = h, h

	case KindResolvedHost:
		h, err := NormalizeFQDN(firstNonBlank(r.Hostname, r.Value))
		if err != nil {
			return Record{}, err
		}
		if !s.InScopeHostname(h) {
			return Record{}, fmt.Errorf("resolved hostname %q is outside scope", h)
		}
		if len(r.Addresses) == 0 && len(r.CNAMEs) == 0 {
			return Record{}, errors.New("resolved_host requires at least one A/AAAA address or CNAME")
		}
		addrs := make([]string, 0, len(r.Addresses))
		seenAddr := map[string]struct{}{}
		for _, raw := range r.Addresses {
			addr, err := netip.ParseAddr(strings.TrimSpace(raw))
			if err != nil {
				return Record{}, fmt.Errorf("invalid resolved address %q: %w", raw, err)
			}
			v := addr.Unmap().String()
			if _, ok := seenAddr[v]; !ok {
				seenAddr[v] = struct{}{}
				addrs = append(addrs, v)
			}
		}
		cnames := make([]string, 0, len(r.CNAMEs))
		seenCNAME := map[string]struct{}{}
		for _, raw := range r.CNAMEs {
			c, err := NormalizeFQDN(raw)
			if err != nil {
				return Record{}, fmt.Errorf("invalid CNAME %q: %w", raw, err)
			}
			if _, ok := seenCNAME[c]; !ok {
				seenCNAME[c] = struct{}{}
				cnames = append(cnames, c)
			}
		}
		sort.Strings(addrs)
		sort.Strings(cnames)
		r.Value, r.Hostname, r.Addresses, r.CNAMEs = h, h, addrs, cnames

	case KindIP:
		v := firstNonBlank(r.IP, r.Value)
		addr, err := netip.ParseAddr(strings.TrimSpace(v))
		if err != nil {
			return Record{}, fmt.Errorf("invalid IP %q: %w", v, err)
		}
		ip := addr.Unmap().String()
		if !s.InScopeIP(ip) {
			if !(s.allowDerivedIPs && r.Derived && s.InScopeHostname(r.Hostname)) {
				return Record{}, fmt.Errorf("IP %q is not explicitly in scope; derived IP probing is disabled", ip)
			}
		}
		r.Value, r.IP = ip, ip

	case KindCIDR:
		v := firstNonBlank(r.CIDR, r.Value)
		p, err := netip.ParsePrefix(strings.TrimSpace(v))
		if err != nil {
			return Record{}, fmt.Errorf("invalid CIDR %q: %w", v, err)
		}
		p = p.Masked()
		if !s.InScopePrefix(p.String()) {
			return Record{}, fmt.Errorf("CIDR %q is outside explicit network scope", p)
		}
		r.Value, r.CIDR = p.String(), p.String()

	case KindService:
		if r.Port < 1 || r.Port > 65535 {
			return Record{}, fmt.Errorf("service port %d is outside 1..65535", r.Port)
		}
		proto := strings.ToLower(strings.TrimSpace(r.Protocol))
		if proto == "" {
			proto = "tcp"
		}
		if proto != "tcp" && proto != "udp" {
			return Record{}, fmt.Errorf("unsupported service protocol %q", proto)
		}
		if strings.TrimSpace(r.IP) != "" {
			addr, err := netip.ParseAddr(strings.TrimSpace(r.IP))
			if err != nil {
				return Record{}, fmt.Errorf("invalid service IP %q: %w", r.IP, err)
			}
			r.IP = addr.Unmap().String()
			if !s.InScopeIP(r.IP) && !(s.allowDerivedIPs && r.Derived && s.InScopeHostname(r.Hostname)) {
				return Record{}, fmt.Errorf("service IP %q is outside explicit network scope", r.IP)
			}
		} else {
			h, err := NormalizeFQDN(r.Hostname)
			if err != nil {
				return Record{}, errors.New("service requires a valid IP or hostname")
			}
			if !s.allowDerivedIPs {
				return Record{}, errors.New("hostname-derived service probing requires allow-derived-ips")
			}
			if !s.InScopeHostname(h) {
				return Record{}, fmt.Errorf("service hostname %q is outside scope", h)
			}
			r.Hostname = h
		}
		r.Protocol = proto
		r.Value = serviceValue(r)

	case KindHTTPTarget:
		canonical, err := NormalizeHTTPURL(firstNonBlank(r.URL, r.Value))
		if err != nil {
			return Record{}, err
		}
		if !s.InScopeURL(canonical) {
			return Record{}, fmt.Errorf("HTTP target %q is outside scope", canonical)
		}
		if r.Status < 0 || r.Status > 999 {
			return Record{}, fmt.Errorf("invalid HTTP status %d", r.Status)
		}
		u, _ := url.Parse(canonical)
		r.URL, r.Value, r.Hostname = canonical, canonical, strings.ToLower(u.Hostname())
		if p := u.Port(); p != "" {
			r.Port, _ = strconv.Atoi(p)
		} else if u.Scheme == "https" {
			r.Port = 443
		} else {
			r.Port = 80
		}

	case KindURL:
		canonical, err := NormalizeHTTPURL(firstNonBlank(r.URL, r.Value))
		if err != nil {
			return Record{}, err
		}
		if !s.InScopeURL(canonical) {
			return Record{}, fmt.Errorf("URL %q is outside scope", canonical)
		}
		r.URL, r.Value = canonical, canonical

	case KindParameterizedURL:
		canonical, err := NormalizeHTTPURL(firstNonBlank(r.URL, r.Value))
		if err != nil {
			return Record{}, err
		}
		if !s.InScopeURL(canonical) {
			return Record{}, fmt.Errorf("parameterized URL %q is outside scope", canonical)
		}
		param := strings.TrimSpace(r.Parameter)
		if param == "" {
			return Record{}, errors.New("parameterized_url requires a parameter name")
		}
		if len(param) > 256 || strings.ContainsAny(param, "\r\n\x00") {
			return Record{}, errors.New("parameter name failed length/control-character checks")
		}
		r.URL, r.Value, r.Parameter = canonical, canonical, param

	case KindPayload:
		family := strings.ToLower(strings.TrimSpace(r.PayloadFamily))
		if family == "" || strings.TrimSpace(r.Value) == "" {
			return Record{}, errors.New("payload requires payload_family and value")
		}
		if len(r.Value) > 1<<20 {
			return Record{}, errors.New("payload exceeds 1 MiB contract limit")
		}
		r.PayloadFamily = family

	case KindFinding:
		if strings.TrimSpace(r.Tool) == "" || strings.TrimSpace(r.Value) == "" {
			return Record{}, errors.New("finding requires tool and target value")
		}
		severity := strings.ToLower(strings.TrimSpace(r.Severity))
		if severity == "" {
			severity = "info"
		}
		if !validSeverity(severity) {
			return Record{}, fmt.Errorf("invalid finding severity %q", severity)
		}
		if len(r.Evidence) > 4<<20 {
			return Record{}, errors.New("finding evidence exceeds 4 MiB contract limit")
		}
		r.Severity = severity

	default:
		return Record{}, fmt.Errorf("unknown record kind %q", r.Kind)
	}
	return r, nil
}

func NormalizeFQDN(raw string) (string, error) {
	host := strings.ToLower(strings.TrimSpace(raw))
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return "", errors.New("FQDN must be 1..253 bytes")
	}
	for i := 0; i < len(host); i++ {
		if host[i] > 0x7f {
			return "", errors.New("non-ASCII hostnames must be supplied in punycode form")
		}
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", errors.New("FQDN must contain at least one dot")
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return "", errors.New("FQDN label must be 1..63 bytes")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("FQDN label cannot start or end with '-'")
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", fmt.Errorf("invalid FQDN character %q", c)
			}
		}
	}
	return host, nil
}

func NormalizeHTTPURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("URL scheme must be http or https")
	}
	if u.Hostname() == "" {
		return "", errors.New("URL requires a host")
	}

	hostname := strings.ToLower(u.Hostname())
	if addr, parseErr := netip.ParseAddr(hostname); parseErr == nil {
		hostname = addr.Unmap().String()
	} else {
		hostname, err = NormalizeFQDN(hostname)
		if err != nil {
			return "", fmt.Errorf("URL host: %w", err)
		}
	}

	port := u.Port()
	if port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return "", fmt.Errorf("invalid URL port %q", port)
		}
		if (scheme == "http" && p == 80) || (scheme == "https" && p == 443) {
			port = ""
		}
	}
	if port != "" {
		u.Host = net.JoinHostPort(hostname, port)
	} else if strings.Contains(hostname, ":") {
		u.Host = "[" + hostname + "]"
	} else {
		u.Host = hostname
	}
	u.Scheme = scheme
	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	q := u.Query()
	for key := range q {
		sort.Strings(q[key])
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func firstNonBlank(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func serviceValue(r Record) string {
	host := r.IP
	if host == "" {
		host = r.Hostname
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(r.Port) + "/" + r.Protocol
}

func validSeverity(v string) bool {
	switch v {
	case "info", "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}
