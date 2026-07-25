package com.victor.reconloop;

import org.junit.Test;

import java.net.URI;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.*;

public class ApiSurfaceEngineTest {

    // ---- looksLikeOpenApi ----

    @Test
    public void recognisesSwaggerAndOpenApiMarkersWithPaths() {
        assertTrue(ApiSurfaceEngine.looksLikeOpenApi("{\"swagger\":\"2.0\",\"paths\":{}}"));
        assertTrue(ApiSurfaceEngine.looksLikeOpenApi("{\"openapi\":\"3.0.0\",\"paths\":{}}"));
    }

    @Test
    public void rejectsMarkerWithoutPathsOrPathsWithoutMarker() {
        assertFalse(ApiSurfaceEngine.looksLikeOpenApi("{\"openapi\":\"3.0.0\"}"));
        assertFalse(ApiSurfaceEngine.looksLikeOpenApi("{\"paths\":{}}"));
        assertFalse(ApiSurfaceEngine.looksLikeOpenApi(null));
    }

    // ---- extractOpenApiPaths ----

    @Test
    public void extractsAndResolvesDocumentedPaths() {
        String body = "{\"openapi\":\"3.0.0\",\"paths\":{\"/users\":{\"get\":{}},\"/users/{id}\":{\"get\":{}}}}";
        Set<String> paths = ApiSurfaceEngine.extractOpenApiPaths(body, URI.create("https://api.example.com/spec.json"));
        assertTrue(paths.contains("https://api.example.com/users"));
        assertTrue(paths.contains("https://api.example.com/users/1"));
    }

    @Test
    public void extractOpenApiPathsReturnsEmptyForMissingPathsBlock() {
        assertTrue(ApiSurfaceEngine.extractOpenApiPaths("{}", URI.create("https://api.example.com/")).isEmpty());
        assertTrue(ApiSurfaceEngine.extractOpenApiPaths(null, URI.create("https://api.example.com/")).isEmpty());
        assertTrue(ApiSurfaceEngine.extractOpenApiPaths("{\"paths\":{}}", null).isEmpty());
    }

    // ---- looksLikeGraphQlEndpoint ----

    @Test
    public void recognisesCommonGraphQlUrlShapes() {
        assertTrue(ApiSurfaceEngine.looksLikeGraphQlEndpoint("https://api.example.com/graphql"));
        assertTrue(ApiSurfaceEngine.looksLikeGraphQlEndpoint("https://api.example.com/gql"));
        assertTrue(ApiSurfaceEngine.looksLikeGraphQlEndpoint("https://api.example.com/v1/graphql"));
        assertFalse(ApiSurfaceEngine.looksLikeGraphQlEndpoint("https://api.example.com/users"));
        assertFalse(ApiSurfaceEngine.looksLikeGraphQlEndpoint(null));
    }

    // ---- analyzeIntrospection / describe ----

    @Test
    public void disabledIntrospectionIsReportedAsDisabled() {
        ApiSurfaceEngine.IntrospectionDetail detail = ApiSurfaceEngine.analyzeIntrospection("{\"errors\":[{\"message\":\"introspection disabled\"}]}");
        assertFalse(detail.enabled());
        assertEquals("introspection appears disabled (no __schema in response)", ApiSurfaceEngine.describe(detail));
    }

    @Test
    public void nullBodyIsReportedAsDisabled() {
        assertFalse(ApiSurfaceEngine.analyzeIntrospection(null).enabled());
    }

    @Test
    public void enabledIntrospectionCountsTypesAndDetectsMutations() {
        String body = "{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"},"
                + "\"mutationType\":{\"name\":\"Mutation\"},"
                + "\"types\":[{\"kind\":\"OBJECT\",\"name\":\"Query\"},{\"kind\":\"OBJECT\",\"name\":\"Mutation\"}]}}}";
        ApiSurfaceEngine.IntrospectionDetail detail = ApiSurfaceEngine.analyzeIntrospection(body);
        assertTrue(detail.enabled());
        assertEquals(2, detail.typeCount());
        assertTrue(detail.mutationsPresent());
    }

    @Test
    public void nullMutationTypeMeansNoMutationsPresent() {
        String body = "{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"},\"mutationType\":null,"
                + "\"types\":[{\"kind\":\"OBJECT\",\"name\":\"Query\"}]}}}";
        assertFalse(ApiSurfaceEngine.analyzeIntrospection(body).mutationsPresent());
    }

    @Test
    public void flagsSensitiveSoundingFieldNamesByKeyword() {
        String body = "{\"data\":{\"__schema\":{\"mutationType\":{\"name\":\"Mutation\"},\"types\":["
                + "{\"kind\":\"OBJECT\",\"name\":\"Mutation\",\"fields\":["
                + "{\"name\":\"deleteUser\"},{\"name\":\"resetPassword\"},{\"name\":\"listPosts\"}]}]}}}";
        List<String> sensitive = ApiSurfaceEngine.analyzeIntrospection(body).sensitiveNames();
        assertTrue(sensitive.contains("deleteUser"));
        assertTrue(sensitive.contains("resetPassword"));
        assertFalse(sensitive.contains("listPosts"));
    }

    @Test
    public void describeIncludesSensitiveNamesWhenPresent() {
        ApiSurfaceEngine.IntrospectionDetail detail = new ApiSurfaceEngine.IntrospectionDetail(
                true, 12, true, List.of("deleteUser", "isAdmin"));
        String description = ApiSurfaceEngine.describe(detail);
        assertTrue(description.contains("ENABLED"));
        assertTrue(description.contains("mutations present"));
        assertTrue(description.contains("deleteUser, isAdmin"));
    }

    // ---- hasGlobalSecurityRequirement ----

    @Test
    public void detectsTopLevelSecurityRequirementOutsidePaths() {
        String body = "{\"openapi\":\"3.0.0\",\"security\":[{\"bearerAuth\":[]}],\"paths\":{\"/users\":{\"get\":{}}}}";
        assertTrue(ApiSurfaceEngine.hasGlobalSecurityRequirement(body));
    }

    @Test
    public void securityKeyOnlyInsidePathsIsNotGlobal() {
        String body = "{\"openapi\":\"3.0.0\",\"paths\":{\"/users\":{\"get\":{\"security\":[{\"bearerAuth\":[]}]}}}}";
        assertFalse(ApiSurfaceEngine.hasGlobalSecurityRequirement(body));
    }

    @Test
    public void noSecurityAnywhereIsNotGlobal() {
        assertFalse(ApiSurfaceEngine.hasGlobalSecurityRequirement("{\"openapi\":\"3.0.0\",\"paths\":{}}"));
        assertFalse(ApiSurfaceEngine.hasGlobalSecurityRequirement(null));
    }

    // ---- findAuthOptOutOperations ----

    @Test
    public void findsOperationExplicitlyOptingOutOfAuth() {
        String body = "{\"openapi\":\"3.0.0\",\"security\":[{\"bearerAuth\":[]}],\"paths\":{"
                + "\"/public/health\":{\"get\":{\"security\":[]}},"
                + "\"/users\":{\"get\":{}}"
                + "}}";
        Set<String> optOuts = ApiSurfaceEngine.findAuthOptOutOperations(body, URI.create("https://api.example.com/spec.json"));
        assertEquals(Set.of("https://api.example.com/public/health"), optOuts);
    }

    @Test
    public void noOptOutsWhenNoOperationDeclaresEmptySecurity() {
        String body = "{\"openapi\":\"3.0.0\",\"security\":[{\"bearerAuth\":[]}],\"paths\":{\"/users\":{\"get\":{}}}}";
        assertTrue(ApiSurfaceEngine.findAuthOptOutOperations(body, URI.create("https://api.example.com/spec.json")).isEmpty());
    }

    @Test
    public void findAuthOptOutOperationsHandlesMissingInput() {
        assertTrue(ApiSurfaceEngine.findAuthOptOutOperations(null, URI.create("https://api.example.com/")).isEmpty());
        assertTrue(ApiSurfaceEngine.findAuthOptOutOperations("{}", null).isEmpty());
        assertTrue(ApiSurfaceEngine.findAuthOptOutOperations("{\"paths\":{}}", URI.create("https://api.example.com/")).isEmpty());
    }
}
