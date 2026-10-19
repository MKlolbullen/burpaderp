package recon

import "fmt"

// CheckProfileEgress resolves the canonical profile, rather than trusting caller-supplied metadata.
// HTTP-capable target producers stay blocked even with every RunPolicy flag granted. Process flags,
// output validation and a matching run ID cannot enforce downstream requests or redirect hops.
func CheckProfileEgress(tool string) error {
	profile, ok := CommandProfileFor(tool)
	if !ok {
		return fmt.Errorf("tool %s has no pinned executable egress profile", tool)
	}
	switch profile.Egress {
	case EgressProvider, EgressDNS, EgressTCP:
		return nil
	case EgressTargetHTTP:
		return fmt.Errorf("tool %s is disabled: target HTTP requests cannot yet be enforced by the shared outbound gateway (#44)", profile.Tool)
	default:
		return fmt.Errorf("tool %s has unknown egress; execution is disabled", profile.Tool)
	}
}
