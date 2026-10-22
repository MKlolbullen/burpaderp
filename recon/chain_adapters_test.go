package recon

import "testing"

func TestNamedChainAdaptersUseExplicitURLFieldsAndKeepProviderProvenance(t *testing.T) {
	for _, fixture := range []struct{ tool, line, source string }{
		{"gospider", `{"type":"url","output":"https://example.com/app.js"}`, "gospider"},
		{"jsfinder", "https://example.com/app.js", "jsfinder"},
		{"waybackurls", "https://example.com/app.js", "waybackurls"},
		{"waybackpy", "https://example.com/app.js", "waybackpy"},
		{"urlfinder", `{"url":"https://example.com/app.js","source":"commoncrawl"}`, "urlfinder:commoncrawl"},
	} {
		records, err := ParseToolOutputLine(fixture.tool, fixture.line)
		if err != nil || len(records) != 1 || records[0].Kind != KindURL || records[0].URL != "https://example.com/app.js" || records[0].Source != fixture.source {
			t.Fatal(fixture, records, err)
		}
	}
	for _, fixture := range []struct{ tool, line string }{{"gospider", `{"output":"example.com"}`}, {"gospider", "https://example.com/app.js"}, {"jsfinder", "[URL] https://example.com/app.js"}} {
		if _, err := ParseToolOutputLine(fixture.tool, fixture.line); err == nil {
			t.Fatal("guessed URL from unsupported format", fixture)
		}
	}
}
