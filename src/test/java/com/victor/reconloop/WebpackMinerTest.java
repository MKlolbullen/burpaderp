package com.victor.reconloop;

import org.junit.Test;

import java.net.URI;
import java.util.Set;

import static org.junit.Assert.*;

public class WebpackMinerTest {

    @Test
    public void recognisesWebpackRuntimeMarkers() {
        assertTrue(WebpackMiner.looksLikeWebpack("var x = __webpack_require__(42);"));
        assertTrue(WebpackMiner.looksLikeWebpack("self.webpackChunkapp = self.webpackChunkapp || [];"));
        assertFalse(WebpackMiner.looksLikeWebpack("function add(a, b) { return a + b; }"));
    }

    @Test
    public void reconstructsChunkUrlRelativeToBundleWhenNoPublicPath() {
        URI base = URI.create("https://example.com/bundle/main.js");
        String body = "n.u=e=>\"static/js/\"+e+\".\"+{10:\"abcd1234\"}[e]+\".chunk.js\";";

        Set<URI> chunks = WebpackMiner.reconstruct(base, body);

        assertEquals(Set.of(URI.create("https://example.com/bundle/static/js/10.abcd1234.chunk.js")), chunks);
    }

    @Test
    public void reconstructsChunkUrlAgainstExplicitPublicPath() {
        URI base = URI.create("https://example.com/bundle/main.js");
        String body = "n.p=\"https://cdn.example.com/assets/\";"
                + "n.u=e=>\"static/js/\"+e+\".\"+{10:\"abcd1234\"}[e]+\".chunk.js\";";

        Set<URI> chunks = WebpackMiner.reconstruct(base, body);

        assertEquals(Set.of(URI.create("https://cdn.example.com/assets/static/js/10.abcd1234.chunk.js")), chunks);
    }

    @Test
    public void reconstructsEveryEntryInTheChunkIdMap() {
        URI base = URI.create("https://example.com/main.js");
        String body = "n.u=e=>\"c/\"+e+\".\"+{10:\"aaaa\",25:\"bbbb\"}[e]+\".js\";";

        Set<URI> chunks = WebpackMiner.reconstruct(base, body);

        assertEquals(2, chunks.size());
        assertTrue(chunks.contains(URI.create("https://example.com/c/10.aaaa.js")));
        assertTrue(chunks.contains(URI.create("https://example.com/c/25.bbbb.js")));
    }

    @Test
    public void ignoresAutoPublicPathSentinel() {
        URI base = URI.create("https://example.com/bundle/main.js");
        String body = "n.p=\"auto\";n.u=e=>\"static/js/\"+e+\".\"+{10:\"abcd1234\"}[e]+\".chunk.js\";";

        Set<URI> chunks = WebpackMiner.reconstruct(base, body);

        assertEquals(Set.of(URI.create("https://example.com/bundle/static/js/10.abcd1234.chunk.js")), chunks);
    }

    @Test
    public void bodyWithNoRuntimeTemplateYieldsNoChunks() {
        Set<URI> chunks = WebpackMiner.reconstruct(URI.create("https://example.com/main.js"), "console.log('hi');");
        assertTrue(chunks.isEmpty());
    }

    @Test
    public void nullBaseOrBodyYieldsNoChunks() {
        assertTrue(WebpackMiner.reconstruct(null, "n.u=e=>\"c/\"+e+{10:\"a\"}[e];").isEmpty());
        assertTrue(WebpackMiner.reconstruct(URI.create("https://example.com/"), null).isEmpty());
    }
}
