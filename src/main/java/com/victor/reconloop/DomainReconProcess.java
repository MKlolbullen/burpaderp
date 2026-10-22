package com.victor.reconloop;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/** The only Java process launcher: a fixed passive reconctl subcommand, never a shell/tool override. */
final class DomainReconProcess {
    static final List<String> TOOLS = List.of("assetfinder", "subfinder", "chaos");
    static final Set<String> LLM_KEYS = Set.of("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "XAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "VENICE_API_KEY");
    record Plan(String domain, String executable, Path outputDir, String runId, int maxHosts, int toolSeconds) {
        Plan {
            domain = DomainReconProcess.domain(domain);
            if (executable == null || executable.isBlank() || executable.indexOf('\0') >= 0 || executable.contains("\n"))
                throw new IllegalArgumentException("Choose the trusted reconctl executable.");
            executable = executable.strip();
            outputDir = Objects.requireNonNull(outputDir, "Choose an output directory.").toAbsolutePath().normalize();
            if (runId == null || !runId.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))
                throw new IllegalArgumentException("Invalid run UUID.");
            if (maxHosts < 1 || maxHosts > 25000 || toolSeconds < 5 || toolSeconds > 1200)
                throw new IllegalArgumentException("Hosts must be 1..25000; tool deadline 5..1200 seconds.");
        }
        List<String> command() {
            return List.of(executable, "enumerate", "--domain", domain, "--output-dir", outputDir.toString(),
                    "--run-id", runId, "--max-hosts", Integer.toString(maxHosts), "--tool-timeout-seconds", Integer.toString(toolSeconds));
        }
        Path runDir() { return outputDir.resolve(domain).resolve(runId); }
        String preview() {
            return "Domain: " + domain + "\nRun: " + runId + "\nOutput: " + runDir()
                    + "\n\nPassive provider queries: assetfinder --subs-only; subfinder -all -recursive; chaos -d."
                    + "\nTools must be installed on PATH; Chaos reads PDCP_API_KEY/config. No API keys in argv."
                    + "\nTrusted installed binaries; this is not an OS sandbox. No automatic Burp scope changes."
                    + "\nMaximum " + maxHosts + " unique hosts; " + toolSeconds + " seconds per tool; bounded output."
                    + "\n\nFiles: subs.txt (new hosts only), sorted_subs.txt, hosts.jsonl, summary.json, httpx-plan.json."
                    + "\nImport hosts separately; the importer rechecks current Burp scope."
                    + "\n\nHTTPX: BLOCKED pending shared outbound policy (#44). The saved plan requests IP, technology,"
                    + " CNAME, TLS, server, title, status, length, location and timing metadata. No probing runs."
                    + "\n\nExact argument vector (JSON):\n" + Json.write(command());
        }
    }
    record Event(String type, String tool, String state, String host, int count, String detail) {}
    record Outcome(String state, int count, String detail) {}
    @FunctionalInterface interface Launcher { Process start(List<String> command) throws IOException; }
    private final Launcher launcher;

    DomainReconProcess() { this(DomainReconProcess::launch); }
    DomainReconProcess(Launcher launcher) { this.launcher = launcher; }

    static String domain(String raw) {
        if (raw == null) throw new IllegalArgumentException("Enter a bare ASCII/punycode domain.");
        String value = raw.strip().toLowerCase(Locale.ROOT);
        if (value.endsWith(".")) value = value.substring(0, value.length() - 1);
        String[] labels = value.split("\\.", -1);
        if (value.length() > 253 || labels.length < 2 || labels[labels.length - 1].matches("[0-9]+"))
            throw new IllegalArgumentException("Enter a bare ASCII/punycode domain, without URL, IP, port or wildcard.");
        for (String label : labels) if (!label.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"))
            throw new IllegalArgumentException("Enter a bare ASCII/punycode domain, without URL, IP, port or wildcard.");
        return value;
    }

    private static Process launch(List<String> command) throws IOException {
        ProcessBuilder builder = new ProcessBuilder(command);
        // Provider tools retain their own configuration; unrelated AI credentials need not cross this boundary.
        removeLlmCredentials(builder.environment());
        builder.redirectError(ProcessBuilder.Redirect.DISCARD); // Never echo raw provider stderr/credentials into Burp.
        return builder.start();
    }

    static void removeLlmCredentials(Map<String, String> environment) {
        environment.keySet().removeIf(key -> LLM_KEYS.contains(key.toUpperCase(Locale.ROOT)));
    }

    Outcome run(Plan plan, Consumer<Event> events) {
        if (Thread.currentThread().isInterrupted()) return new Outcome("CANCELLED", 0, "Cancelled before launch.");
        Process process;
        try { process = launcher.start(plan.command()); }
        catch (IOException e) { return new Outcome("FAILED", 0, "Could not launch reconctl. Check executable and permissions."); }
        Set<ProcessHandle> descendants = new HashSet<>();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3L * plan.toolSeconds() + 15);
        Protocol protocol = new Protocol(plan);
        try (InputStream input = process.getInputStream()) {
            process.getOutputStream().close();
            long bytes = 0;
            int lines = 0;
            ByteArrayOutputStream line = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            while (true) {
                if (Thread.currentThread().isInterrupted()) throw new InterruptedException();
                if (System.nanoTime() > deadline) return new Outcome("TIMEOUT", protocol.count(), "Overall deadline reached; partial files may remain.");
                captureChildren(process, descendants);
                int available = input.available();
                if (available == 0) {
                    if (!process.isAlive()) break;
                    Thread.sleep(20);
                    continue;
                }
                // One reader; never wait for EOF on a pipe an escaped child may hold.
                int size = input.read(chunk, 0, Math.min(chunk.length, available));
                if (size < 0) break;
                for (int i = 0; i < size; i++) {
                    int next = Byte.toUnsignedInt(chunk[i]);
                    if (++bytes > (32L << 20) || line.size() >= (16 << 10)) throw new IOException("protocol output limit");
                    if (next != '\n') { line.write(next); continue; }
                    if (++lines > plan.maxHosts() + 5) throw new IOException("event limit");
                    Event event = protocol.accept(line.toString(StandardCharsets.UTF_8)); line.reset();
                    events.accept(event);
                }
            }
            if (line.size() != 0) throw new IOException("incomplete event");
            if (!process.waitFor(2, TimeUnit.SECONDS)) throw new IOException("sidecar did not exit");
            return protocol.finish(process.exitValue());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Outcome("CANCELLED", protocol.count(), "Cancelled; partial files may be available.");
        } catch (IOException | RuntimeException e) {
            boolean cancelled = Thread.currentThread().isInterrupted();
            return new Outcome(cancelled ? "CANCELLED" : "FAILED", protocol.count(),
                    cancelled ? "Job stopped; partial files may be available."
                            : "Sidecar output failed validation or was incomplete. Check summary.json; raw stderr is not displayed.");
        } finally {
            terminate(process, descendants);
        }
    }

    private static void captureChildren(Process process, Set<ProcessHandle> descendants) {
        try (var children = process.descendants()) { children.forEach(descendants::add); }
        catch (UnsupportedOperationException | SecurityException ignored) { /* Test doubles/unsupported platform. */ }
    }
    private static void terminate(Process process, Set<ProcessHandle> descendants) {
        captureChildren(process, descendants);
        // Process.destroy may close a pipe while another thread holds its read lock.
        // Signal via ProcessHandle first; only close streams after forceful cleanup.
        try { process.toHandle().destroy(); }
        catch (UnsupportedOperationException e) { process.destroy(); }
        for (ProcessHandle child : descendants) if (child.isAlive()) child.destroy();
        boolean interrupted = Thread.interrupted();
        try { process.waitFor(1, TimeUnit.SECONDS); }
        catch (InterruptedException e) { interrupted = true; }
        for (ProcessHandle child : descendants) if (child.isAlive()) child.destroyForcibly();
        if (process.isAlive()) process.destroyForcibly();
        try { process.getInputStream().close(); process.getOutputStream().close(); process.getErrorStream().close(); }
        catch (IOException ignored) {}
        if (interrupted) Thread.currentThread().interrupt();
    }

    /** Enforce correlation, scope, stage order, terminal state and bounded unique host counts again in Java. */
    static final class Protocol {
        private final Plan plan;
        private final Set<String> hosts = new HashSet<>();
        private boolean started, done;
        private int stage, stageHosts;
        private String terminal;
        private boolean degraded;
        Protocol(Plan plan) { this.plan = plan; }
        int count() { return hosts.size(); }
        Event accept(String line) {
            Map<String, Object> obj = Json.asObject(Json.parseStrict(line));
            require(obj != null && obj.keySet().stream().allMatch(Set.of("version", "type", "run_id", "domain", "state", "count", "tool_result", "record")::contains));
            require(integer(obj, "version") == 1 && plan.runId().equals(obj.get("run_id")) && plan.domain().equals(obj.get("domain")) && !done);
            String type = string(obj, "type");
            String state = obj.containsKey("state") ? string(obj, "state") : "";
            String tool = "", host = "", detail = "";
            switch (type) {
                case "start" -> { require(!started && state.equals("RUNNING") && !obj.containsKey("record") && !obj.containsKey("tool_result")); started = true; }
                case "host" -> {
                    require(started && stage < TOOLS.size() && state.isEmpty() && !obj.containsKey("tool_result"));
                    Map<String, Object> wire = Json.asObject(obj.get("record"));
                    require(wire != null && wire.keySet().stream().allMatch(Set.of("kind", "value", "hostname", "tool", "source", "run_id", "created_at")::contains));
                    SidecarEvent.Event record = SidecarEvent.parse(Json.write(obj.get("record")));
                    host = domain(record.hostname()); tool = record.tool();
                    require(record.kind() == SidecarEvent.Kind.HOSTNAME && plan.runId().equals(record.runId())
                            && host.equals(record.value()) && host.equals(record.hostname()) && tool.equals(record.source())
                            && TOOLS.get(stage).equals(tool) && (host.equals(plan.domain()) || host.endsWith("." + plan.domain()))
                            && hosts.size() < plan.maxHosts() && hosts.add(host));
                    stageHosts++;
                }
                case "tool" -> {
                    require(started && stage < TOOLS.size() && state.isEmpty() && !obj.containsKey("record"));
                    Map<String, Object> result = Json.asObject(obj.get("tool_result")); require(result != null);
                    tool = string(result, "tool"); state = string(result, "state");
                    require(TOOLS.get(stage).equals(tool) && Set.of("SUCCESS", "PARTIAL", "FAILED", "TIMEOUT", "CANCELLED").contains(state)
                            && integer(result, "added") == stageHosts);
                    degraded |= !state.equals("SUCCESS");
                    Map<String, Object> run = Json.asObject(result.get("run"));
                    require(run != null && plan.runId().equals(run.get("run_id")) && tool.equals(run.get("tool")));
                    // Display only our own status vocabulary, never provider-supplied messages.
                    detail = state.equals("SUCCESS") ? "completed" : "Check summary; output may be partial.";
                    stage++; stageHosts = 0;
                }
                case "done" -> {
                    require(started && !obj.containsKey("record") && !obj.containsKey("tool_result")
                            && Set.of("SUCCESS", "PARTIAL", "FAILED", "CANCELLED").contains(state));
                    if (Set.of("SUCCESS", "PARTIAL").contains(state)) require(stage == TOOLS.size());
                    if (state.equals("SUCCESS")) require(!degraded);
                    terminal = state; done = true;
                }
                default -> throw new IllegalArgumentException("Unknown enumeration event");
            }
            require(integer(obj, "count") == hosts.size());
            return new Event(type, tool, state, host, hosts.size(), detail);
        }
        Outcome finish(int exitCode) {
            require(done && (Set.of("SUCCESS", "PARTIAL").contains(terminal) ? exitCode == 0 : exitCode != 0));
            return new Outcome(terminal, count(), "HTTPX remains blocked. Import hosts separately using current Burp scope.");
        }
        private static void require(boolean value) { if (!value) throw new IllegalArgumentException("Invalid enumeration protocol"); }
        private static String string(Map<String, Object> obj, String key) {
            Object value = obj.get(key); require(value instanceof String); return (String) value;
        }
        private static int integer(Map<String, Object> obj, String key) {
            Object value = obj.get(key); require(value instanceof Number);
            double number = ((Number) value).doubleValue(); require(number >= 0 && number <= Integer.MAX_VALUE && number == Math.rint(number));
            return (int) number;
        }
    }
}
