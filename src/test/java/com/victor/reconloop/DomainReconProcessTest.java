package com.victor.reconloop;

import org.junit.Test;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.Assert.*;

public class DomainReconProcessTest {
    static final String ID = "123e4567-e89b-42d3-a456-426614174000";
    static DomainReconProcess.Plan plan() { return new DomainReconProcess.Plan("Example.COM.", "reconctl", Path.of("recon output"), ID, 5, 5); }
    static Map<String, Object> event(String type, int count) {
        var obj = new LinkedHashMap<String, Object>(); obj.put("version", 1); obj.put("type", type); obj.put("run_id", ID); obj.put("domain", "example.com"); obj.put("count", count); return obj;
    }
    static String start() { var obj = event("start", 0); obj.put("state", "RUNNING"); return Json.write(obj); }
    static String host(String name, String tool, int count) {
        var obj = event("host", count); obj.put("record", Map.of("kind","hostname","value",name,"hostname",name,"tool",tool,"source",tool,"run_id",ID)); return Json.write(obj);
    }
    static String tool(String tool, String state, int added, int count) {
        var obj = event("tool", count); obj.put("tool_result", Map.of("tool",tool,"state",state,"added",added,"run",Map.of("tool",tool,"run_id",ID))); return Json.write(obj);
    }
    static String done(String state, int count) { var obj = event("done", count); obj.put("state", state); return Json.write(obj); }
    static String validStream() { return String.join("\n", start(), host("www.example.com","assetfinder",1),tool("assetfinder","SUCCESS",1,1),tool("subfinder","SUCCESS",0,1),tool("chaos","SUCCESS",0,1),done("SUCCESS",1)) + "\n"; }

    @Test public void strictDomainAndFixedImmutableArgumentVector() {
        var plan = plan(); assertEquals("example.com", plan.domain());
        assertEquals(List.of("reconctl","enumerate","--domain","example.com","--output-dir",plan.outputDir().toString(),"--run-id",ID,"--max-hosts","5","--tool-timeout-seconds","5"), plan.command());
        assertThrows(UnsupportedOperationException.class, () -> plan.command().add("--tool"));
        for (String raw : List.of("https://example.com","127.0.0.1","1.2","*.example.com","example.com;id","example.com:443","a..com","éxample.com","-x.example.com","example.com/"))
            assertThrows(raw, IllegalArgumentException.class, () -> DomainReconProcess.domain(raw));
        assertEquals("xn--bcher-kva.example", DomainReconProcess.domain("xn--bcher-kva.example"));
        assertThrows(IllegalArgumentException.class, () -> new DomainReconProcess.Plan("example.com", "reconctl", Path.of("."), ID, 25001,5));
        assertThrows(IllegalArgumentException.class, () -> new DomainReconProcess.Plan("example.com", "reconctl", Path.of("."), "../escape", 5,5));
    }

    @Test public void unrelatedKeysAreRemovedWithoutChangingProviderConfig() {
        Map<String,String> env = new HashMap<>();
        for (String name : DomainReconProcess.LLM_KEYS) env.put(name.toLowerCase(Locale.ROOT), "fixture");
        env.put("PDCP_API_KEY", "provider-fixture"); env.put("PATH", "/bin");
        DomainReconProcess.removeLlmCredentials(env);
        assertEquals(Map.of("PDCP_API_KEY", "provider-fixture", "PATH", "/bin"), env);
    }

    @Test public void protocolRequiresCorrelationScopeUniqueCountsAndStageOrder() {
        for (String bad : List.of(host("outside.test","assetfinder",1), host("evil-example.com","assetfinder",1),
                host("a.example.com","subfinder",1),host("a.example.com","assetfinder",3),
                host("a.example.com","assetfinder",1).replace(ID,"00000000-0000-0000-0000-000000000000"),
                host("a.example.com","assetfinder",1).replace("\"kind\":\"hostname\"","\"kind\":\"url\""),
                tool("subfinder","SUCCESS",0,0), done("SUCCESS",0))) {
            var protocol = new DomainReconProcess.Protocol(plan()); protocol.accept(start());
            assertThrows(bad, IllegalArgumentException.class, () -> protocol.accept(bad));
        }
        var protocol = new DomainReconProcess.Protocol(plan()); protocol.accept(start());
        protocol.accept(host("a.example.com","assetfinder",1));
        assertThrows(IllegalArgumentException.class, () -> protocol.accept(host("a.example.com","assetfinder",2)));
    }

    @Test public void protocolRejectsMissingTerminalContradictoryExitAndSuccessAfterFailure() {
        var protocol = new DomainReconProcess.Protocol(plan()); protocol.accept(start());
        assertThrows(IllegalArgumentException.class, () -> protocol.finish(0));
        protocol.accept(tool("assetfinder","FAILED",0,0)); protocol.accept(tool("subfinder","SUCCESS",0,0)); protocol.accept(tool("chaos","SUCCESS",0,0));
        assertThrows(IllegalArgumentException.class, () -> protocol.accept(done("SUCCESS",0)));
        var good = new DomainReconProcess.Protocol(plan()); validStream().lines().forEach(good::accept);
        assertEquals("SUCCESS", good.finish(0).state());
        assertThrows(IllegalArgumentException.class, () -> good.finish(2));
        assertThrows(IllegalArgumentException.class, () -> good.accept(done("SUCCESS",1)));
    }

    @Test public void runnerValidatesBoundedOutputAndAlwaysCleansUp() {
        var fake = new FakeProcess(validStream()); AtomicReference<List<String>> argv = new AtomicReference<>();
        var runner = new DomainReconProcess(command -> { argv.set(command); return fake; });
        List<DomainReconProcess.Event> events = new ArrayList<>(); var outcome = runner.run(plan(), events::add);
        assertEquals("SUCCESS", outcome.state()); assertEquals(1, outcome.count()); assertEquals(plan().command(),argv.get()); assertTrue(fake.destroyed); assertEquals(6, events.size());
        for (String output : List.of(validStream().substring(0,validStream().length()-1), "x".repeat(17000), start()+"\n", "not json\n")) {
            var invalid = new FakeProcess(output);
            assertEquals("FAILED", new DomainReconProcess(command -> invalid).run(plan(), e -> {}).state()); assertTrue(invalid.destroyed);
        }
    }

    @Test public void interruptedJobNeverLaunches() {
        Thread.currentThread().interrupt();
        try { assertEquals("CANCELLED", new DomainReconProcess(command -> { fail("launched"); return null; }).run(plan(), e -> {}).state()); }
        finally { Thread.interrupted(); }
    }

    @Test public void sharedCatalogCoversRequestedStagesWithoutMakingPlanExecutable() {
        var catalog = ReconChainPlan.create("Example.COM."); assertEquals("PLAN_ONLY", catalog.get("state"));
        var rows = ReconChainPlan.rows(catalog);
        for (String name : List.of("subfinder","assetfinder","chaos-client (chaos)","amass","dnsx","whatweb","httpx","katana","JSFinder","gospider","Waybackpy","waybackurls","urlfinder","cariddi"))
            assertTrue(name, rows.stream().anyMatch(row -> row.tool().equals(name)));
        assertEquals(3, rows.stream().filter(row -> row.mode().equals("ENUMERATION_JOB")).count());
        assertTrue(rows.stream().filter(row -> row.tool().equals("httpx")).allMatch(row -> row.mode().equals("BLOCKED_TARGET_HTTP")));
        assertTrue(rows.stream().filter(row -> row.tool().equals("Waybackpy")).allMatch(row -> row.detail().contains("Exclude SavePageNow")));
    }

    @Test public void actualFixedLauncherHandlesExecutableWithSpacesAndNoShellInterpolation() throws Exception {
        org.junit.Assume.assumeFalse(System.getProperty("os.name").startsWith("Windows"));
        Path dir = Files.createTempDirectory("recon job "); Path script = dir.resolve("fixture reconctl");
        Files.writeString(script, "#!/bin/sh\n[ \"$1\" = enumerate ] || exit 8\n[ \"$3\" = example.com ] || exit 9\ncat <<'FIXTURE'\n"+validStream()+"FIXTURE\n", StandardCharsets.UTF_8);
        assertTrue(script.toFile().setExecutable(true));
        var plan = new DomainReconProcess.Plan("example.com",script.toString(),dir,ID,5,5);
        assertEquals("SUCCESS",new DomainReconProcess().run(plan,e -> {}).state());
        Files.delete(script); Files.delete(dir);
    }

    @Test public void actualSidecarRoundTripWithOfflineProviderFixtures() throws Exception {
        String binary = System.getenv("RECONCTL_TEST_BINARY");
        org.junit.Assume.assumeTrue("CI builds the sidecar for this integration test", binary != null);
        Path dir = Files.createTempDirectory("recon-sidecar-test");
        for (String name : DomainReconProcess.TOOLS) {
            Path script = dir.resolve(name);
            Files.writeString(script,"#!/bin/sh\nprintf '%s\\n' a.example.com b.example.com a.example.com outside.test\n"+(name.equals("chaos")?"exit 7\n":""));
            assertTrue(script.toFile().setExecutable(true));
        }
        Path wrapper = dir.resolve("reconctl-fixture");
        Files.writeString(wrapper,"#!/bin/sh\nexport PATH='"+dir.toString().replace("'","'\\''")+"'\nexec '"+binary.replace("'","'\\''")+"' \"$@\"\n");
        assertTrue(wrapper.toFile().setExecutable(true));
        var plan = new DomainReconProcess.Plan("example.com", wrapper.toString(), dir.resolve("runs"), ID,5,5);
        List<DomainReconProcess.Event> events = new ArrayList<>();
        var outcome = new DomainReconProcess().run(plan, events::add);
        assertEquals("PARTIAL",outcome.state()); assertEquals(2,outcome.count());
        assertEquals("a.example.com\nb.example.com\n",Files.readString(plan.runDir().resolve("sorted_subs.txt")));
        assertTrue(Files.readString(plan.runDir().resolve("httpx-plan.json")).contains("BLOCKED"));
        assertEquals(2,events.stream().filter(e -> e.type().equals("host")).count());
        try (var files = Files.walk(dir)) { for (Path path : files.sorted(Comparator.reverseOrder()).toList()) Files.delete(path); }
    }

    @Test public void cancellationStopsRealChildProcessesAndUnblocksInheritedOutputPipe() throws Exception {
        org.junit.Assume.assumeFalse(System.getProperty("os.name").startsWith("Windows"));
        Path dir = Files.createTempDirectory("recon-cancel-test"); Path pid = dir.resolve("child.pid"), script = dir.resolve("reconctl");
        Files.writeString(script,"#!/bin/sh\ntrap 'wait; exit 0' TERM\n/bin/sleep 30 &\necho $! > '"+pid+"'\nwait\n"); assertTrue(script.toFile().setExecutable(true));
        var plan = new DomainReconProcess.Plan("example.com",script.toString(),dir,ID,5,5);
        AtomicReference<DomainReconProcess.Outcome> outcome = new AtomicReference<>();
        Thread worker = new Thread(() -> outcome.set(new DomainReconProcess().run(plan,e -> {}))); worker.start();
        long until = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(3);
        while (!Files.exists(pid) && System.nanoTime() < until) Thread.sleep(10);
        assertTrue("fixture started",Files.exists(pid));
        long childPid = Long.parseLong(Files.readString(pid).strip());
        Thread.sleep(150); worker.interrupt(); worker.join(4000);
        if (worker.isAlive()) {
            StringBuilder trace = new StringBuilder("reader/cancellation stuck\n");
            trace.append(Arrays.toString(worker.getStackTrace()));
            fail(trace.toString());
        }
        assertEquals("CANCELLED",outcome.get().state());
        assertFalse("child still running",ProcessHandle.of(childPid).map(ProcessHandle::isAlive).orElse(false));
        Files.delete(pid); Files.delete(script); Files.delete(dir);
    }

    static final class FakeProcess extends Process {
        final InputStream stdout; boolean destroyed;
        FakeProcess(String output) { stdout = new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8)); }
        public OutputStream getOutputStream() { return OutputStream.nullOutputStream(); }
        public InputStream getInputStream() { return stdout; }
        public InputStream getErrorStream() { return InputStream.nullInputStream(); }
        public int waitFor() { return 0; }
        public int exitValue() { return 0; }
        public void destroy() { destroyed = true; }
    }
}
