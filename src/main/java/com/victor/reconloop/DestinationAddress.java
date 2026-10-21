package com.victor.reconloop;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Pure literal parsing/classification. No resolver, InetAddress parsing, or network access. */
final class DestinationAddress {
    enum Kind { NAME, PUBLIC, PROTECTED, INVALID }
    record Host(Kind kind, String canonical) {}
    private static final Set<String> METADATA = Set.of(
            "metadata.google.internal", "metadata.google", "metadata.aws.internal", "instance-data");

    static Host inspect(String raw) {
        if (raw == null || raw.isBlank() || raw.length() > 255) return new Host(Kind.INVALID, "");
        String host = raw.toLowerCase(Locale.ROOT);
        if (!host.equals(host.strip()) || host.contains("%")) return new Host(Kind.INVALID, "");
        if (host.startsWith("[") || host.endsWith("]")) {
            if (!host.startsWith("[") || !host.endsWith("]")) return new Host(Kind.INVALID, "");
            host = host.substring(1, host.length() - 1);
            if (host.indexOf(':') < 0) return new Host(Kind.INVALID, "");
        }
        if (host.indexOf(':') >= 0) {
            byte[] bytes = ipv6(host);
            if (bytes == null) return new Host(Kind.INVALID, "");
            // Normalize mapped IPv4 to canonical dotted decimal before handing it to Burp.
            boolean mapped = true;
            for (int i = 0; i < 10; i++) mapped &= bytes[i] == 0;
            mapped &= (bytes[10] & 255) == 255 && (bytes[11] & 255) == 255;
            if (mapped) return ipv4Result(new int[]{bytes[12] & 255, bytes[13] & 255, bytes[14] & 255, bytes[15] & 255});
            int first = bytes[0] & 255, second = bytes[1] & 255;
            // Conservative public-unicast allow range; reject transition/special-use/documentation space.
            boolean blocked = (first & 0xe0) != 0x20
                    || (first == 0x20 && second == 0x02) // 6to4 embeds another destination.
                    || (first == 0x20 && second == 0x01 && (bytes[2] & 254) == 0)
                    || (first == 0x20 && second == 0x01 && (bytes[2] & 255) == 0x0d && (bytes[3] & 255) == 0xb8)
                    || (first == 0x3f && second == 0xff && (bytes[2] & 0xf0) == 0); // 3fff::/20 documentation.
            StringBuilder canonical = new StringBuilder();
            for (int i = 0; i < 16; i += 2) {
                if (i > 0) canonical.append(':');
                canonical.append(Integer.toHexString(((bytes[i] & 255) << 8) | (bytes[i + 1] & 255)));
            }
            return new Host(blocked ? Kind.PROTECTED : Kind.PUBLIC, canonical.toString());
        }
        String name = host.endsWith(".") ? host.substring(0, host.length() - 1) : host;
        if (name.equals("localhost") || name.endsWith(".localhost") || METADATA.contains(name))
            return new Host(Kind.PROTECTED, name);
        int[] v4 = ipv4(host);
        if (v4 != null) return ipv4Result(v4);
        // Historical integer, abbreviated, hexadecimal and octal IP forms must never reach DNS/Burp.
        if (name.matches("[0-9.]+") || name.matches("(?i)(?:0x[0-9a-f]+|[0-9]+)(?:\\.(?:0x[0-9a-f]+|[0-9]+))*"))
            return new Host(Kind.INVALID, "");
        if (name.length() > 253 || !name.matches("[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")) return new Host(Kind.INVALID, "");
        for (String label : name.split("\\.", -1))
            if (label.isEmpty() || label.length() > 63 || label.startsWith("-") || label.endsWith("-")) return new Host(Kind.INVALID, "");
        return new Host(Kind.NAME, name);
    }

    private static Host ipv4Result(int[] b) {
        int a = b[0], c = b[1], d = b[2];
        boolean blocked = a == 0 || a == 10 || a == 127 || a >= 224
                || (a == 100 && c >= 64 && c <= 127) || (a == 169 && c == 254)
                || (a == 172 && c >= 16 && c <= 31) || (a == 192 && c == 168)
                || (a == 192 && c == 0 && (d == 0 || d == 2)) || (a == 192 && c == 88 && d == 99)
                || (a == 198 && (c == 18 || c == 19)) || (a == 198 && c == 51 && d == 100)
                || (a == 203 && c == 0 && d == 113)
                || (a == 168 && c == 63 && d == 129 && b[3] == 16); // Azure platform virtual IP.
        return new Host(blocked ? Kind.PROTECTED : Kind.PUBLIC, a + "." + c + "." + d + "." + b[3]);
    }

    private static int[] ipv4(String host) {
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4) return null;
        int[] bytes = new int[4];
        for (int i = 0; i < 4; i++) {
            String part = parts[i];
            if (!part.matches("[0-9]{1,3}") || (part.length() > 1 && part.charAt(0) == '0')) return null;
            bytes[i] = Integer.parseInt(part);
            if (bytes[i] > 255) return null;
        }
        return bytes;
    }

    private static byte[] ipv6(String host) {
        if (!host.matches("[0-9a-f:.]+")) return null;
        String[] halves = host.split("::", -1);
        if (halves.length > 2) return null;
        List<Integer> left = groups(halves[0]);
        List<Integer> right = halves.length == 2 ? groups(halves[1]) : List.of();
        if (left == null || right == null || (halves.length == 2 && halves[0].contains("."))) return null;
        int size = left.size() + right.size();
        if (halves.length == 1 ? size != 8 : size >= 8) return null;
        byte[] bytes = new byte[16];
        int index = 0;
        for (int value : left) { bytes[index++] = (byte) (value >> 8); bytes[index++] = (byte) value; }
        index = 16 - right.size() * 2;
        for (int value : right) { bytes[index++] = (byte) (value >> 8); bytes[index++] = (byte) value; }
        return bytes;
    }

    private static List<Integer> groups(String half) {
        if (half.isEmpty()) return List.of();
        List<Integer> groups = new ArrayList<>();
        String[] tokens = half.split(":", -1);
        for (int i = 0; i < tokens.length; i++) {
            String token = tokens[i];
            if (token.contains(".")) {
                if (i != tokens.length - 1) return null;
                int[] bytes = ipv4(token);
                if (bytes == null) return null;
                groups.add(bytes[0] * 256 + bytes[1]); groups.add(bytes[2] * 256 + bytes[3]);
            } else {
                if (!token.matches("[0-9a-f]{1,4}")) return null;
                groups.add(Integer.parseInt(token, 16));
            }
        }
        return groups;
    }
}
