package com.victor.reconloop.contracts;

import org.junit.Test;

import java.net.URI;
import java.util.List;

import static org.junit.Assert.*;

public class PayloadRouterTest {

    private static Asset.ParameterizedUrl target(String name, PayloadFamily hint) {
        return new Asset.ParameterizedUrl(URI.create("https://api.example.com/x"), name,
                ParamLocation.QUERY, hint, "profiler");
    }

    @Test
    public void routesOnlyCompatibleHints() {
        PayloadRouter router = new PayloadRouter();
        List<Asset.ParameterizedUrl> pool = List.of(
                target("q", PayloadFamily.XSS),
                target("id", PayloadFamily.SQLI),
                target("file", PayloadFamily.LFI),
                target("cmd", PayloadFamily.RCE)
        );

        List<Asset.ParameterizedUrl> xss = router.route(PayloadFamily.XSS, pool);
        assertEquals(1, xss.size());
        assertEquals("q", xss.get(0).name());

        assertTrue(router.route(PayloadFamily.RCE, pool).isEmpty());
        assertEquals(1, new PayloadRouter(true).route(PayloadFamily.RCE, pool).size());
    }

    @Test
    public void mapsProfilerAndManifestLabels() {
        assertEquals(PayloadFamily.SQLI, PayloadRouter.hintFromProfilerClass("SQLi"));
        assertEquals(PayloadFamily.LFI, PayloadRouter.hintFromProfilerClass("LFI/path traversal"));
        assertEquals(PayloadFamily.RCE, PayloadRouter.hintFromProfilerClass("Command/RCE"));
        assertEquals(PayloadFamily.IDOR, PayloadRouter.hintFromProfilerClass("IDOR/BOLA"));
        assertEquals(PayloadFamily.SQLI, PayloadRouter.fromManifestCategory("sqli2"));
        assertEquals(PayloadFamily.RCE, PayloadRouter.fromManifestCategory("rce_payloads"));
        assertEquals(PayloadFamily.SSRF, PayloadRouter.fromManifestCategory("ssrf"));
        assertEquals(PayloadFamily.OPEN_REDIRECT, PayloadRouter.fromManifestCategory("redirect"));
        assertEquals(PayloadFamily.CRLF, PayloadRouter.fromManifestCategory("crlf"));
        assertEquals(PayloadFamily.GRAPHQL, PayloadRouter.fromManifestCategory("graphql"));
        assertEquals(PayloadFamily.GENERIC, PayloadRouter.fromManifestCategory("unknown-pack"));
    }

    @Test
    public void ssrfAndRedirectAreCrossCompatible() {
        PayloadRouter router = new PayloadRouter();
        Asset.ParameterizedUrl url = target("next", PayloadFamily.OPEN_REDIRECT);
        Asset.ParameterizedUrl dest = target("dest", PayloadFamily.SSRF);
        assertTrue(router.compatible(PayloadFamily.SSRF, url));
        assertTrue(router.compatible(PayloadFamily.OPEN_REDIRECT, dest));
        assertFalse(router.compatible(PayloadFamily.GRAPHQL, url));
    }
}
