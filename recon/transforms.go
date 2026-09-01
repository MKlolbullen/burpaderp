package recon

import (
	"errors"
	"fmt"
	"strings"
)

// ResolvedHostToIPs is the explicit resolved_host -> ip contract boundary. The
// output is marked Derived so the network-probe socket can distinguish DNS
// provenance from an explicitly authorised IP/CIDR.
func ResolvedHostToIPs(record Record) ([]Record, error) {
	if record.Kind != KindResolvedHost {
		return nil, fmt.Errorf("resolved-host transform requires %s, got %s", KindResolvedHost, record.Kind)
	}
	if record.Hostname == "" || len(record.Addresses) == 0 {
		return nil, errors.New("resolved_host has no hostname/A/AAAA addresses")
	}
	out := make([]Record, 0, len(record.Addresses))
	for _, address := range record.Addresses {
		out = append(out, Record{
			Kind: KindIP, IP: address, Value: address, Hostname: record.Hostname,
			Derived: true, Source: record.Source, RunID: record.RunID,
		})
	}
	return out, nil
}

// ResolvedHostToHostname deliberately keeps the in-scope hostname rather than
// substituting its IP. This is the preferred path into httpx because Host/SNI
// semantics remain intact and shared/CDN IPs are not accidentally treated as
// standalone authorised targets.
func ResolvedHostToHostname(record Record) (Record, error) {
	if record.Kind != KindResolvedHost {
		return Record{}, fmt.Errorf("resolved-host transform requires %s, got %s", KindResolvedHost, record.Kind)
	}
	if strings.TrimSpace(record.Hostname) == "" {
		return Record{}, errors.New("resolved_host has no hostname")
	}
	return Record{
		Kind: KindHostname, Hostname: record.Hostname, Value: record.Hostname,
		Source: record.Source, RunID: record.RunID,
	}, nil
}

// DedupeRecords performs canonical de-duplication after records have passed
// Scope.Validate. It preserves first-seen order and provenance on the retained
// record.
func DedupeRecords(records []Record) []Record {
	seen := make(map[string]struct{}, len(records))
	out := make([]Record, 0, len(records))
	for _, record := range records {
		key := RecordKey(record)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, record)
	}
	return out
}

func RecordKey(record Record) string {
	switch record.Kind {
	case KindDomain, KindHostname, KindIP, KindCIDR:
		return string(record.Kind) + "\x00" + record.Value
	case KindResolvedHost:
		return string(record.Kind) + "\x00" + record.Hostname + "\x00" + strings.Join(record.Addresses, ",") + "\x00" + strings.Join(record.CNAMEs, ",")
	case KindService:
		return string(record.Kind) + "\x00" + record.Value
	case KindHTTPTarget, KindURL:
		return string(record.Kind) + "\x00" + record.URL
	case KindParameterizedURL:
		return string(record.Kind) + "\x00" + record.URL + "\x00" + record.Parameter
	case KindPayload:
		return string(record.Kind) + "\x00" + record.PayloadFamily + "\x00" + record.Value
	case KindFinding:
		return string(record.Kind) + "\x00" + record.Tool + "\x00" + record.Value + "\x00" + record.Source
	default:
		return string(record.Kind) + "\x00" + record.Value
	}
}
