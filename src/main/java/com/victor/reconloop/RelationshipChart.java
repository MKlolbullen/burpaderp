package com.victor.reconloop;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Relationship view of hosts, ports, and script files that are already in the plugin tables.
 * It does not scan, import, or change scope.
 */
final class RelationshipChart {
    static final int HOST_CAP = 120;
    static final int PORT_CAP = 100;
    static final int FILE_CAP = 80;

    record Node(String id, String kind, String label, String detail) {}

    record Edge(String source, String target, String verb) {}

    static final class Body {
        final Node node;
        double x;
        double y;
        double vx;
        double vy;
        boolean fixed;

        Body(Node node, double x, double y) {
            this.node = node;
            this.x = x;
            this.y = y;
        }
    }

    private final List<Node> nodes;
    private final List<Edge> edges;
    private final List<Body> bodies;
    private final String notice;
    private final String json;
    private double alpha = 1;

    private RelationshipChart(List<Node> nodes, List<Edge> edges, List<Body> bodies, String notice, String json) {
        this.nodes = List.copyOf(nodes);
        this.edges = List.copyOf(edges);
        this.bodies = bodies;
        this.notice = notice;
        this.json = json;
    }

    static RelationshipChart build(List<ReconModel.AssetRow> assets, List<ReconModel.DiscoveryRow> discoveries) {
        Map<String, HostAcc> hosts = new LinkedHashMap<>();
        Map<String, NetAcc> nets = new LinkedHashMap<>();
        Map<String, PortAcc> ports = new LinkedHashMap<>();
        Map<String, FileAcc> files = new LinkedHashMap<>();
        java.util.Set<String> droppedHosts = new java.util.LinkedHashSet<>();
        List<String> notes = new ArrayList<>();

        if (assets != null) {
            for (ReconModel.AssetRow row : assets) {
                if (row == null || row.value() == null) continue;
                switch (row.type() == null ? "" : row.type()) {
                    case "host" -> addHost(hosts, row.value(), "", row.value(), droppedHosts);
                    case "ipv4", "ipv6" -> {
                        if (addHost(hosts, row.value(), row.value(), "", droppedHosts)) {
                            String prefix = prefixOf(row.value());
                            if (prefix != null) nets.computeIfAbsent(prefix, NetAcc::new).hosts.add(hostId(row.value()));
                        }
                    }
                    case "service" -> addService(hosts, ports, row.value(), droppedHosts);
                    default -> { }
                }
            }
        }
        if (discoveries != null) {
            for (ReconModel.DiscoveryRow row : discoveries) {
                if (row == null) continue;
                addUrl(hosts, ports, files, row.url(), droppedHosts);
            }
        }
        for (HostAcc host : hosts.values()) {
            String prefix = prefixOf(host.ip);
            if (prefix == null) continue;
            NetAcc net = nets.computeIfAbsent(prefix, NetAcc::new);
            if (!net.hosts.contains(host.id)) net.hosts.add(host.id);
        }
        if (!droppedHosts.isEmpty()) notes.add("Showing " + HOST_CAP + " hosts. " + droppedHosts.size() + " were left out.");
        if (ports.size() > PORT_CAP) {
            notes.add("Too many ports to draw. Shared script files are still tied to their hosts.");
        }
        int hiddenFiles = Math.max(0, files.size() - FILE_CAP);
        if (hiddenFiles > 0) notes.add(hiddenFiles + " more script files were left off the chart.");

        List<Node> nodes = new ArrayList<>();
        List<Edge> edges = new ArrayList<>();
        Map<String, Node> byId = new LinkedHashMap<>();
        for (NetAcc net : nets.values()) {
            if (net.hosts.isEmpty()) continue;
            Node node = new Node("net:" + net.label, "net", net.label,
                    net.hosts.size() == 1 ? "1 host" : net.hosts.size() + " hosts");
            nodes.add(node);
            byId.put(node.id, node);
        }
        for (HostAcc host : hosts.values()) {
            int open = host.ports.size();
            String detail = host.ip.isBlank() ? host.name : host.ip;
            if (!host.name.isBlank() && !host.ip.isBlank() && !host.name.equals(host.ip)) detail = host.name + " · " + host.ip;
            detail = detail + (open == 0 ? " · no open ports" : " · " + open + " open");
            Node node = new Node(host.id, "host", host.label(), detail);
            nodes.add(node);
            byId.put(node.id, node);
            NetAcc net = nets.get(prefixOf(host.ip));
            if (net != null) link(edges, "net:" + net.label, host.id, "holds");
        }
        boolean drawPorts = ports.size() <= PORT_CAP;
        if (drawPorts) {
            for (PortAcc port : ports.values()) {
                Node node = new Node(port.id, "port", port.port + "/" + port.proto, port.service.isBlank() ? port.proto : port.service);
                nodes.add(node);
                byId.put(node.id, node);
                link(edges, port.hostId, port.id, "exposes");
            }
        }
        int drawnFiles = 0;
        for (FileAcc file : files.values()) {
            if (drawnFiles >= FILE_CAP) break;
            Node node = new Node(file.id, "file", file.label,
                    file.hosts.size() == 1 ? "Served by 1 host." : "Served by " + file.hosts.size() + " hosts.");
            nodes.add(node);
            byId.put(node.id, node);
            drawnFiles++;
            for (String source : file.sources) {
                String host = portHost(source);
                if (drawPorts && byId.containsKey(source)) link(edges, source, file.id, "serves");
                else if (byId.containsKey(host)) link(edges, host, file.id, "serves");
            }
        }
        List<Body> bodies = layout(nodes);
        return new RelationshipChart(nodes, edges, bodies, String.join(" ", notes), json(hosts, files));
    }

    List<Node> nodes() { return nodes; }
    List<Edge> edges() { return edges; }
    List<Body> bodies() { return bodies; }
    String notice() { return notice; }
    String meridianJson() { return json; }
    boolean empty() { return nodes.stream().noneMatch(node -> "host".equals(node.kind)); }

    boolean step() {
        if (alpha < 0.02) return false;
        int n = bodies.size();
        for (int i = 0; i < n; i++) {
            Body a = bodies.get(i);
            for (int j = i + 1; j < n; j++) {
                Body b = bodies.get(j);
                double dx = a.x - b.x;
                double dy = a.y - b.y;
                double d2 = dx * dx + dy * dy;
                if (d2 < 1) { dx = 0.2; dy = 0.2; d2 = dx * dx + dy * dy; }
                if (d2 > 280 * 280) continue;
                double d = Math.sqrt(d2);
                double f = (1800 / d2) * alpha;
                if (!a.fixed) { a.vx += dx / d * f; a.vy += dy / d * f; }
                if (!b.fixed) { b.vx -= dx / d * f; b.vy -= dy / d * f; }
            }
        }
        Map<String, Body> byId = new LinkedHashMap<>();
        for (Body body : bodies) byId.put(body.node.id, body);
        for (Edge edge : edges) {
            Body a = byId.get(edge.source);
            Body b = byId.get(edge.target);
            if (a == null || b == null) continue;
            double dx = b.x - a.x;
            double dy = b.y - a.y;
            double d = Math.max(1, Math.hypot(dx, dy));
            double f = (d - 90) * 0.04 * alpha;
            if (!a.fixed) { a.vx += dx / d * f; a.vy += dy / d * f; }
            if (!b.fixed) { b.vx -= dx / d * f; b.vy -= dy / d * f; }
        }
        for (Body body : bodies) {
            if (body.fixed) { body.vx = 0; body.vy = 0; continue; }
            body.vx *= 0.72;
            body.vy *= 0.72;
            body.x += Math.max(-8, Math.min(8, body.vx));
            body.y += Math.max(-8, Math.min(8, body.vy));
        }
        alpha *= 0.985;
        return alpha >= 0.02;
    }

    void move(String id, double x, double y) {
        for (Body body : bodies) {
            if (body.node.id.equals(id)) {
                body.x = x;
                body.y = y;
                body.vx = 0;
                body.vy = 0;
                body.fixed = true;
                alpha = Math.max(alpha, 0.35);
            }
        }
    }

    Body hit(double x, double y) {
        Body found = null;
        double best = 14 * 14;
        for (Body body : bodies) {
            double d = (body.x - x) * (body.x - x) + (body.y - y) * (body.y - y);
            if (d <= best) { best = d; found = body; }
        }
        return found;
    }

    private static boolean addHost(Map<String, HostAcc> hosts, String label, String ip, String name,
                                   java.util.Set<String> dropped) {
        String id = hostId(label);
        if (hosts.containsKey(id)) {
            HostAcc host = hosts.get(id);
            if (host.ip.isBlank() && !ip.isBlank()) host.ip = ip;
            if (host.name.isBlank() && !name.isBlank()) host.name = name;
            return true;
        }
        if (hosts.size() >= HOST_CAP) {
            dropped.add(id);
            return false;
        }
        hosts.put(id, new HostAcc(id, ip, name));
        return true;
    }

    private static void addService(Map<String, HostAcc> hosts, Map<String, PortAcc> ports, String value,
                                   java.util.Set<String> dropped) {
        int slash = value.lastIndexOf('/');
        int colon = value.lastIndexOf(':');
        if (slash < 0 || colon < 0 || colon > slash) return;
        String host = value.substring(0, colon).trim();
        int port;
        try { port = Integer.parseInt(value.substring(colon + 1, slash).trim()); }
        catch (NumberFormatException e) { return; }
        if (port < 1 || port > 65535 || host.isBlank()) return;
        String proto = value.substring(slash + 1).trim().toLowerCase(Locale.ROOT);
        if (proto.isBlank()) proto = "tcp";
        if (!addHost(hosts, host, isIp(host) ? host : "", isIp(host) ? "" : host, dropped)) return;
        String id = "port:" + hostKey(host) + ":" + proto + ":" + port;
        ports.putIfAbsent(id, new PortAcc(id, hostId(host), port, proto, serviceName(port, proto)));
        hosts.get(hostId(host)).ports.put(id, ports.get(id));
    }

    private static void addUrl(Map<String, HostAcc> hosts, Map<String, PortAcc> ports, Map<String, FileAcc> files,
                               String raw, java.util.Set<String> dropped) {
        if (raw == null || raw.isBlank()) return;
        URI uri;
        try { uri = URI.create(raw.trim()); }
        catch (IllegalArgumentException e) { return; }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) return;
        String host = uri.getHost();
        if (host == null || host.isBlank()) return;
        host = host.toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
        int port = uri.getPort();
        if (port < 0) port = scheme.equals("https") ? 443 : 80;
        if (!addHost(hosts, host, isIp(host) ? host : "", isIp(host) ? "" : host, dropped)) return;
        String proto = "tcp";
        String portId = "port:" + hostKey(host) + ":" + proto + ":" + port;
        ports.putIfAbsent(portId, new PortAcc(portId, hostId(host), port, proto, scheme));
        hosts.get(hostId(host)).ports.put(portId, ports.get(portId));
        String kind = fileKind(uri.getPath());
        if (kind.isBlank()) return;
        String path = uri.getPath() == null || uri.getPath().isBlank() ? "/" : uri.getPath();
        String key = path.toLowerCase(Locale.ROOT);
        FileAcc file = files.computeIfAbsent(key, ignored -> new FileAcc("file:" + key, labelOf(path), kind, raw));
        file.hosts.add(hostId(host));
        file.sources.add(portId);
        if (!isIp(host)) return;
        file.addresses.add(host);
    }

    private static String json(Map<String, HostAcc> hosts, Map<String, FileAcc> files) {
        List<Object> hostRows = new ArrayList<>();
        for (HostAcc host : hosts.values()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("ip", host.ip);
            row.put("names", host.name.isBlank() ? List.of() : List.of(host.name));
            row.put("up", true);
            List<Object> portRows = new ArrayList<>();
            for (PortAcc port : host.ports.values()) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("port", port.port);
                item.put("proto", port.proto);
                item.put("state", "open");
                item.put("service", port.service);
                item.put("product", "");
                item.put("version", "");
                portRows.add(item);
            }
            row.put("ports", portRows);
            hostRows.add(row);
        }
        List<Object> fileRows = new ArrayList<>();
        int drawn = 0;
        for (FileAcc file : files.values()) {
            if (drawn >= FILE_CAP) break;
            drawn++;
            for (String address : file.addresses) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("url", file.url);
                row.put("kind", file.kind);
                row.put("status", 200);
                row.put("ip", address);
                fileRows.add(row);
            }
        }
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("meridian", 1);
        root.put("target", "burp-scope");
        root.put("hosts", hostRows);
        root.put("dns", List.of());
        root.put("pages", List.of());
        root.put("files", fileRows);
        return Json.write(root);
    }

    private static List<Body> layout(List<Node> nodes) {
        Map<String, Integer> seen = new LinkedHashMap<>();
        List<Body> bodies = new ArrayList<>();
        for (Node node : nodes) {
            int i = seen.getOrDefault(node.kind, 0);
            seen.put(node.kind, i + 1);
            double angle = switch (node.kind) {
                case "net" -> -0.4;
                case "host" -> 1.2;
                case "port" -> 2.6;
                default -> 4.4;
            };
            angle += i * 0.55;
            double radius = 80 + (i % 5) * 36;
            bodies.add(new Body(node, Math.cos(angle) * radius, Math.sin(angle) * radius));
        }
        return bodies;
    }

    private static void link(List<Edge> edges, String source, String target, String verb) {
        for (Edge edge : edges) {
            if (edge.source.equals(source) && edge.target.equals(target) && edge.verb.equals(verb)) return;
        }
        edges.add(new Edge(source, target, verb));
    }

    static String fileKind(String path) {
        if (path == null || path.isBlank()) return "";
        String base = path;
        int query = base.indexOf('?');
        if (query >= 0) base = base.substring(0, query);
        int slash = base.lastIndexOf('/');
        String name = (slash >= 0 ? base.substring(slash + 1) : base).toLowerCase(Locale.ROOT);
        if (name.endsWith(".chunk") || name.contains(".chunk.")) return "chunk";
        if (name.endsWith(".map")) return "map";
        if (name.endsWith(".json")) return "json";
        if (name.endsWith(".js")) return "js";
        if (name.endsWith(".ts")) return "ts";
        return "";
    }

    private static String portHost(String portId) {
        if (portId == null || !portId.startsWith("port:")) return "";
        int last = portId.lastIndexOf(':');
        int prev = last < 0 ? -1 : portId.lastIndexOf(':', last - 1);
        if (prev < "port:".length()) return "";
        return "host:" + portId.substring("port:".length(), prev);
    }

    private static String labelOf(String path) {
        int slash = path.lastIndexOf('/');
        String name = slash >= 0 ? path.substring(slash + 1) : path;
        if (name.isBlank()) name = path;
        return name.length() > 56 ? name.substring(0, 53) + "…" : name;
    }

    private static String prefixOf(String ip) {
        if (ip == null || ip.isBlank()) return null;
        if (isIpv4(ip)) {
            String[] parts = ip.split("\\.");
            return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24";
        }
        if (ip.indexOf(':') < 0) return null;
        String[] parts = ip.toLowerCase(Locale.ROOT).split(":");
        StringBuilder prefix = new StringBuilder();
        int kept = 0;
        for (String part : parts) {
            if (part.isBlank()) break;
            if (kept == 4) break;
            if (kept > 0) prefix.append(':');
            prefix.append(part);
            kept++;
        }
        return kept == 0 ? null : prefix + "::/64";
    }

    private static boolean isIp(String value) { return isIpv4(value) || (value != null && value.indexOf(':') >= 0); }

    private static boolean isIpv4(String value) {
        if (value == null || !value.matches("\\d{1,3}(?:\\.\\d{1,3}){3}")) return false;
        for (String part : value.split("\\.")) if (Integer.parseInt(part) > 255) return false;
        return true;
    }

    private static String hostId(String host) { return "host:" + hostKey(host); }

    private static String hostKey(String host) { return host.toLowerCase(Locale.ROOT); }

    private static String serviceName(int port, String proto) {
        if ("udp".equals(proto)) return "udp";
        return switch (port) {
            case 80, 8080, 8000, 3000 -> "http";
            case 443, 8443 -> "https";
            case 22 -> "ssh";
            case 53 -> "domain";
            default -> proto;
        };
    }

    private static final class HostAcc {
        final String id;
        String ip;
        String name;
        final Map<String, PortAcc> ports = new LinkedHashMap<>();
        HostAcc(String id, String ip, String name) { this.id = id; this.ip = ip; this.name = name; }
        String label() { return !name.isBlank() ? name : ip; }
    }

    private static final class NetAcc {
        final String label;
        final List<String> hosts = new ArrayList<>();
        NetAcc(String label) { this.label = label; }
    }

    private static final class PortAcc {
        final String id;
        final String hostId;
        final int port;
        final String proto;
        final String service;
        PortAcc(String id, String hostId, int port, String proto, String service) {
            this.id = id; this.hostId = hostId; this.port = port; this.proto = proto; this.service = service;
        }
    }

    private static final class FileAcc {
        final String id;
        final String label;
        final String kind;
        final String url;
        final java.util.Set<String> hosts = new java.util.LinkedHashSet<>();
        final java.util.Set<String> sources = new java.util.LinkedHashSet<>();
        final java.util.Set<String> addresses = new java.util.LinkedHashSet<>();
        FileAcc(String id, String label, String kind, String url) {
            this.id = id; this.label = label; this.kind = kind; this.url = url;
        }
    }
}
