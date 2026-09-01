package com.victor.reconloop.contracts;

import java.net.InetAddress;
import java.net.UnknownHostException;

final class NetAddresses {
    private NetAddresses() {}

    static Parsed parse(String raw) {
        if (raw == null) return Parsed.fail("empty address");
        String s = raw.strip();
        if (s.isEmpty()) return Parsed.fail("empty address");

        int slash = s.lastIndexOf('/');
        String addrPart = slash < 0 ? s : s.substring(0, slash);
        Integer prefix = null;
        if (slash >= 0) {
            try {
                prefix = Integer.parseInt(s.substring(slash + 1));
            } catch (NumberFormatException e) {
                return Parsed.fail("invalid CIDR prefix");
            }
        }

        InetAddress addr;
        try {
            addr = InetAddress.getByName(addrPart);
        } catch (UnknownHostException e) {
            return Parsed.fail("unparseable IP");
        }
        if (!addr.getHostAddress().equalsIgnoreCase(stripV6Brackets(addrPart))
                && !isNormalizedLiteral(addrPart, addr)) {
            return Parsed.fail("hostname supplied where an IP was required");
        }

        boolean ipv6 = addr.getAddress().length == 16;
        int maxPrefix = ipv6 ? 128 : 32;
        int prefixLength = prefix == null ? maxPrefix : prefix;
        if (prefixLength < 0 || prefixLength > maxPrefix) return Parsed.fail("CIDR prefix out of range");

        String restriction = restriction(addr);
        boolean cidr = prefix != null && prefixLength < maxPrefix;
        String canonical = cidr ? addr.getHostAddress() + "/" + prefixLength : addr.getHostAddress();
        return new Parsed(canonical, addr, cidr, prefixLength, restriction, null);
    }

    static boolean scanEligible(Parsed parsed, int minIpv4Prefix, int minIpv6Prefix) {
        if (parsed.restriction() != null) return false;
        if (!parsed.cidr()) return true;
        int min = parsed.addr().getAddress().length == 16 ? minIpv6Prefix : minIpv4Prefix;
        return parsed.prefixLength() >= min;
    }

    static String restriction(InetAddress addr) {
        if (addr.isAnyLocalAddress()) return "unspecified address";
        if (addr.isLoopbackAddress()) return "loopback";
        if (addr.isLinkLocalAddress()) return "link-local";
        if (addr.isMulticastAddress()) return "multicast";
        byte[] b = addr.getAddress();
        if (b.length == 4) {
            int a = b[0] & 0xff;
            int c = b[1] & 0xff;
            if (a == 10) return "rfc1918";
            if (a == 172 && c >= 16 && c <= 31) return "rfc1918";
            if (a == 192 && c == 168) return "rfc1918";
            if (a == 169 && c == 254) return "link-local";
            if (a == 127) return "loopback";
            if (a == 0) return "unspecified address";
        }
        if (b.length == 16) {
            if ((b[0] & 0xfe) == 0xfc) return "unique-local";
        }
        return null;
    }

    private static String stripV6Brackets(String s) {
        if (s.startsWith("[") && s.endsWith("]")) return s.substring(1, s.length() - 1);
        return s;
    }

    private static boolean isNormalizedLiteral(String raw, InetAddress addr) {
        String stripped = stripV6Brackets(raw);
        return addr.getHostAddress().equalsIgnoreCase(stripped)
                || raw.contains(":")
                || raw.matches("\\d+\\.\\d+\\.\\d+\\.\\d+");
    }

    record Parsed(String canonical, InetAddress addr, boolean cidr, int prefixLength,
                  String restriction, String error) {
        static Parsed fail(String error) {
            return new Parsed("", null, false, 0, null, error);
        }

        boolean ok() {
            return error == null && addr != null;
        }
    }
}
