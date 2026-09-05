package com.victor.reconloop;

import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class JsonTest {

    @SuppressWarnings("unchecked")
    @Test
    public void parsesNestedObjectWithMixedTypes() {
        String text = "{\"a\":1,\"b\":[1,2,3],\"c\":\"hi\",\"d\":true,\"e\":null,\"f\":{\"g\":2.5}}";
        Object parsed = Json.parse(text);

        Map<String, Object> root = Json.asObject(parsed);
        assertNotNull(root);
        assertEquals(1.0, (double) (Double) root.get("a"), 0.0001);
        assertEquals(List.of(1.0, 2.0, 3.0), root.get("b"));
        assertEquals("hi", root.get("c"));
        assertEquals(Boolean.TRUE, root.get("d"));
        assertTrue(root.containsKey("e"));
        assertNull(root.get("e"));

        Map<String, Object> nested = Json.asObject(root.get("f"));
        assertNotNull(nested);
        assertEquals(2.5, (double) (Double) nested.get("g"), 0.0001);
    }

    @Test
    public void parsesArrayOfObjects() {
        Object parsed = Json.parse("[{\"id\":1},{\"id\":2}]");
        List<Object> array = Json.asArray(parsed);
        assertNotNull(array);
        assertEquals(2, array.size());
        assertEquals(1.0, (double) (Double) Json.asObject(array.get(0)).get("id"), 0.0001);
    }

    @Test
    public void decodesStandardEscapeSequences() {
        Object parsed = Json.parse("\"line1\\nline2\\ttabbed\\\"quoted\\\"\"");
        assertEquals("line1\nline2\ttabbed\"quoted\"", parsed);
    }

    @Test
    public void decodesUnicodeEscape() {
        Object parsed = Json.parse("\"\\u0041\\u0042\\u0043\"");
        assertEquals("ABC", parsed);
    }

    @Test
    public void parsesNumbersBooleansAndNull() {
        assertEquals(42.0, (double) (Double) Json.parse("42"), 0.0001);
        assertEquals(-3.5, (double) (Double) Json.parse("-3.5"), 0.0001);
        assertEquals(Boolean.TRUE, Json.parse("true"));
        assertEquals(Boolean.FALSE, Json.parse("false"));
        assertNull(Json.parse("null"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void throwsOnTruncatedObject() {
        Json.parse("{\"a\":1");
    }

    @Test(expected = IllegalArgumentException.class)
    public void throwsOnEmptyInput() {
        Json.parse("");
    }

    @Test(expected = IllegalArgumentException.class)
    public void throwsOnGarbageInput() {
        Json.parse("not json at all");
    }

    @Test
    public void strHelperTrimsAndStringifiesNonStringValues() {
        Map<String, Object> obj = Json.asObject(Json.parse("{\"a\":\"  padded  \",\"b\":7}"));
        assertEquals("padded", Json.str(obj, "a"));
        assertEquals("7.0", Json.str(obj, "b"));
        assertNull(Json.str(obj, "missing"));
        assertNull(Json.str(null, "a"));
    }

    @Test
    public void asObjectAndAsArrayReturnNullForWrongType() {
        assertNull(Json.asObject(Json.parse("[1,2]")));
        assertNull(Json.asArray(Json.parse("{\"a\":1}")));
    }

    @Test
    public void toleratesTrailingContentAfterRootValue() {
        // Documented as tolerant of trailing content (e.g. prose after an LLM's JSON answer);
        // parse() only reads the first complete value and ignores what follows.
        Object parsed = Json.parse("{\"a\":1} and then some trailing prose");
        assertEquals(1.0, (double) (Double) Json.asObject(parsed).get("a"), 0.0001);
    }

    @Test(expected = IllegalArgumentException.class)
    public void strictParseRejectsTrailingContent() {
        Json.parseStrict("{\"a\":1} trailing");
    }

    // ---- write ----

    @Test
    public void writeRoundTripsNestedStructures() {
        String src = "{\"user\":{\"name\":\"amy\",\"roles\":[\"a\",\"b\"]},\"n\":3,\"ok\":true,\"x\":null}";
        Object tree = Json.parse(src);
        String out = Json.write(tree);
        // Re-parsing the serialised form must yield an equal structure.
        assertEquals(tree, Json.parse(out));
        assertTrue(out.contains("\"name\":\"amy\""));
    }

    @Test
    public void writeRendersIntegralDoublesWithoutADecimalPoint() {
        assertEquals("{\"n\":3}", Json.write(Json.parse("{\"n\":3}")));
        assertEquals("{\"n\":3.5}", Json.write(Json.parse("{\"n\":3.5}")));
    }

    @Test
    public void writeEscapesControlAndQuoteCharacters() {
        String out = Json.write(java.util.Map.of("k", "a\"b\nc"));
        assertTrue(out.contains("\\\""));
        assertTrue(out.contains("\\n"));
    }

    // ---- leafPointers / get / set ----

    @Test
    public void leafPointersEnumeratesEveryPrimitiveLeaf() {
        Object tree = Json.parse("{\"a\":\"x\",\"b\":{\"c\":1},\"d\":[\"e\",true],\"n\":null}");
        java.util.List<String> pointers = Json.leafPointers(tree);
        assertTrue(pointers.contains("/a"));
        assertTrue(pointers.contains("/b/c"));
        assertTrue(pointers.contains("/d/0"));
        assertTrue(pointers.contains("/d/1"));
        assertFalse(pointers.contains("/n"));      // null leaves are not injectable points
        assertFalse(pointers.contains("/b"));      // containers are not leaves
    }

    @Test
    public void setByPointerReplacesObjectAndArrayLeavesInPlace() {
        Object tree = Json.parse("{\"user\":{\"role\":\"guest\"},\"tags\":[\"x\",\"y\"]}");
        assertTrue(Json.setByPointer(tree, "/user/role", "admin"));
        assertTrue(Json.setByPointer(tree, "/tags/1", "z"));
        assertEquals("admin", Json.getByPointer(tree, "/user/role"));
        assertEquals("z", Json.getByPointer(tree, "/tags/1"));
        assertEquals("{\"user\":{\"role\":\"admin\"},\"tags\":[\"x\",\"z\"]}", Json.write(tree));
    }

    @Test
    public void setByPointerFailsOnMissingPathAndOutOfRangeIndex() {
        Object tree = Json.parse("{\"a\":[\"x\"]}");
        assertFalse(Json.setByPointer(tree, "/a/5", "z"));
        assertFalse(Json.setByPointer(tree, "/missing/leaf", "z"));
        assertFalse(Json.setByPointer(tree, "", "z"));
    }

    @Test
    public void pointerTokensWithSlashOrTildeAreEscaped() {
        Object tree = Json.parse("{\"a/b\":\"x\"}");
        java.util.List<String> pointers = Json.leafPointers(tree);
        assertEquals(java.util.List.of("/a~1b"), pointers);
        assertEquals("x", Json.getByPointer(tree, "/a~1b"));
        assertTrue(Json.setByPointer(tree, "/a~1b", "y"));
        assertEquals("y", Json.getByPointer(tree, "/a~1b"));
    }
}
