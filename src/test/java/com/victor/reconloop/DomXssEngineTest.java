package com.victor.reconloop;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class DomXssEngineTest {

    @Test
    public void flagsInnerHtmlAssignedFromLocationHash() {
        // The match span starts at the sink's leading dot (the receiver expression before it is
        // not part of the match) and ends at the end of the captured right-hand side (before the
        // trailing ';'), so it excludes both "el" and the statement terminator.
        String body = "el.innerHTML = location.hash;";
        List<DomXssEngine.DomFinding> findings = DomXssEngine.analyze(body);

        assertEquals(1, findings.size());
        DomXssEngine.DomFinding f = findings.get(0);
        assertEquals("innerHTML", f.sink());
        assertEquals("location.hash", f.source());
        assertEquals(".innerHTML = location.hash", body.substring(f.start(), f.end()));
    }

    @Test
    public void flagsDocumentWriteCallFromLocationSearch() {
        List<DomXssEngine.DomFinding> findings = DomXssEngine.analyze("document.write(location.search);");

        assertTrue(findings.stream().anyMatch(f ->
                f.sink().equals("document.write") && f.source().equals("location.search")));
    }

    @Test
    public void ignoresSinkAssignedFromStaticText() {
        List<DomXssEngine.DomFinding> findings = DomXssEngine.analyze("el.innerHTML = 'static text';");

        assertTrue(findings.isEmpty());
    }

    @Test
    public void ignoresCodeWithNoDangerousSink() {
        List<DomXssEngine.DomFinding> findings = DomXssEngine.analyze("var x = location.hash + 1;");

        assertTrue(findings.isEmpty());
    }

    @Test
    public void offsetsAreBodyRelativeToTheSurroundingContext() {
        String prefix = "// some leading code\nfunction f() {\n  el";
        String matchedSpan = ".outerHTML = document.location.href";
        String body = prefix + matchedSpan + ";\n}\n";

        List<DomXssEngine.DomFinding> findings = DomXssEngine.analyze(body);
        assertEquals(1, findings.size());
        DomXssEngine.DomFinding f = findings.get(0);
        assertEquals(matchedSpan, body.substring(f.start(), f.end()));
    }

    @Test
    public void blankOrNullBodyYieldsNoFindings() {
        assertTrue(DomXssEngine.analyze(null).isEmpty());
        assertTrue(DomXssEngine.analyze("   ").isEmpty());
    }
}
