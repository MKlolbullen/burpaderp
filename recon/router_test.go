package recon

import "testing"

func TestRCEHintFileCannotBeFiredAsPayload(t *testing.T) {
	router := DefaultPayloadRouter()
	_, err := router.Route(
		Record{Kind: KindPayload, PayloadFamily: "rce", Value: "?cmd={payload}"},
		Record{Kind: KindParameterizedURL, URL: "https://api.example.com/run?cmd=x", Parameter: "cmd"},
	)
	if err == nil {
		t.Fatal("rce.txt parameter hints must never route as payloads")
	}
}

func TestRCEPayloadPolicyRequiresSafetyTransforms(t *testing.T) {
	router := DefaultPayloadRouter()
	policy, err := router.Route(
		Record{Kind: KindPayload, PayloadFamily: "rce_payloads", Value: "id"},
		Record{Kind: KindParameterizedURL, URL: "https://api.example.com/run?cmd=x", Parameter: "cmd"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.RequiresDestructiveFilter || !policy.RequiresOASTRewrite {
		t.Fatalf("unsafe RCE routing policy: %#v", policy)
	}
}

func TestPayloadRouterRequiresParameterizedTarget(t *testing.T) {
	router := DefaultPayloadRouter()
	_, err := router.Route(
		Record{Kind: KindPayload, PayloadFamily: "xss", Value: "probe"},
		Record{Kind: KindURL, URL: "https://api.example.com/"},
	)
	if err == nil {
		t.Fatal("payload router should require an explicit injection-point contract")
	}
}
