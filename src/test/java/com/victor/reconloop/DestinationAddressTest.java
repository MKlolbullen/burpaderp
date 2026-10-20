package com.victor.reconloop;

import org.junit.Test;
import java.net.InetAddress;
import java.util.List;
import java.util.Random;
import static org.junit.Assert.*;

public class DestinationAddressTest {
    @Test public void rejectsProtectedAliasesAndSpecialUseRangesWithoutDns() {
        for (String host : List.of("localhost.", "sub.localhost", "metadata.google.internal.", "0.1.2.3", "10.1.2.3",
                "100.64.0.1", "100.100.100.200", "127.0.0.1", "169.254.169.254", "172.31.1.1", "192.168.0.1",
                "192.0.0.8", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.1.2.3", "255.255.255.255",
                "168.63.129.16", "::", "::1", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1", "::ffff:7f00:1", "::127.0.0.1",
                "fc00::1", "fe80::1", "fec0::1", "ff02::1", "64:ff9b::7f00:1", "2002:7f00:1::", "2001::1", "2001:db8::1", "3fff::1")) {
            assertEquals(host, DestinationAddress.Kind.PROTECTED, DestinationAddress.inspect(host).kind());
        }
    }

    @Test public void ambiguousOrMalformedLiteralsNeverBecomeNamesForAnotherResolver() {
        for (String host : List.of("127.1", "2130706433", "0177.0.0.1", "0x7f000001", "0x7f.0.0.1", "127.0.0.01",
                "127.0.0.1.", "999.1.1.1", "fe80::1%eth0", "[fe80::1%25eth0]", "1::2::3", "1:2:3", "1:2:3:4:5:6:7:",
                "1:2:3:4:5:6:7:8::", "::ffff:127.1", "bad::host", "[example.test]", " bad.test", "a..test"))
            assertEquals(host, DestinationAddress.Kind.INVALID, DestinationAddress.inspect(host).kind());
    }

    @Test public void preservesPublicDestinationsAndCanonicalizesMappedIpv4() {
        assertEquals("8.8.8.8", DestinationAddress.inspect("::ffff:808:808").canonical());
        assertEquals(DestinationAddress.Kind.PUBLIC, DestinationAddress.inspect("8.8.8.8").kind());
        assertEquals(DestinationAddress.Kind.PUBLIC, DestinationAddress.inspect("2606:4700:4700::1111").kind());
        assertEquals(DestinationAddress.Kind.NAME, DestinationAddress.inspect("fd.example.test").kind());
        assertEquals("api.example.test", DestinationAddress.inspect("API.EXAMPLE.TEST.").canonical());
    }

    @Test public void ipv6CanonicalizationMatchesByteBasedJdkFormatting() throws Exception {
        Random random = new Random(44);
        for (int i = 0; i < 1000; i++) {
            byte[] bytes = new byte[16]; random.nextBytes(bytes); bytes[0] = 0x26;
            String literal = InetAddress.getByAddress(bytes).getHostAddress(); // No name resolution.
            var address = DestinationAddress.inspect(literal);
            assertEquals(literal, DestinationAddress.Kind.PUBLIC, address.kind());
            assertEquals(literal, address.canonical());
        }
    }
}
