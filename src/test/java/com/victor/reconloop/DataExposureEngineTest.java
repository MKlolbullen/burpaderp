package com.victor.reconloop;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class DataExposureEngineTest {

    // ---- excessive data exposure ----

    @Test
    public void flagsPasswordHashInResponse() {
        String body = "{\"id\":1,\"username\":\"bob\",\"password_hash\":\"$2b$10$abcdefghijklmnopqrstuv\"}";
        List<DataExposureEngine.Field> fields = DataExposureEngine.excessiveDataExposure(body);

        assertEquals(1, fields.size());
        assertEquals("$.password_hash", fields.get(0).path());
        assertEquals("password_hash", fields.get(0).key());
    }

    @Test
    public void flagsNestedSensitiveFieldsInsideArraysAndObjects() {
        String body = "{\"users\":[{\"id\":1,\"ssn\":\"123-45-6789\"},{\"id\":2,\"name\":\"ok\"}]}";
        List<DataExposureEngine.Field> fields = DataExposureEngine.excessiveDataExposure(body);

        assertEquals(1, fields.size());
        assertEquals("$.users[0].ssn", fields.get(0).path());
    }

    @Test
    public void ordinaryProfileResponseIsNotFlagged() {
        String body = "{\"id\":1,\"username\":\"bob\",\"email\":\"bob@example.com\",\"created_at\":\"2024-01-01\"}";
        assertTrue(DataExposureEngine.excessiveDataExposure(body).isEmpty());
    }

    @Test
    public void keyMatchingIsCaseAndSeparatorInsensitive() {
        assertFalse(DataExposureEngine.excessiveDataExposure("{\"apiKey\":\"x\"}").isEmpty());
        assertFalse(DataExposureEngine.excessiveDataExposure("{\"API_KEY\":\"x\"}").isEmpty());
        assertFalse(DataExposureEngine.excessiveDataExposure("{\"api-key\":\"x\"}").isEmpty());
    }

    // ---- mass assignment ----

    @Test
    public void flagsIsAdminInRequestBody() {
        String body = "{\"username\":\"bob\",\"email\":\"bob@example.com\",\"is_admin\":true}";
        List<DataExposureEngine.Field> fields = DataExposureEngine.massAssignmentCandidates(body);

        assertEquals(1, fields.size());
        assertEquals("is_admin", fields.get(0).key());
        assertEquals("true", fields.get(0).valuePreview());
    }

    @Test
    public void flagsMultiplePrivilegedFieldsInOneBody() {
        String body = "{\"name\":\"widget\",\"price\":0.01,\"role\":\"admin\"}";
        List<DataExposureEngine.Field> fields = DataExposureEngine.massAssignmentCandidates(body);

        assertEquals(2, fields.size());
    }

    @Test
    public void ordinarySignupRequestIsNotFlagged() {
        String body = "{\"username\":\"bob\",\"password\":\"hunter2\",\"email\":\"bob@example.com\"}";
        // "password" itself is not on the privileged-request-field list (that's a credential the
        // client is *supposed* to set, unlike role/balance/verified/etc).
        assertTrue(DataExposureEngine.massAssignmentCandidates(body).isEmpty());
    }

    // ---- shared parsing behaviour ----

    @Test
    public void nonJsonBodyYieldsNoFindings() {
        assertTrue(DataExposureEngine.excessiveDataExposure("<html>not json</html>").isEmpty());
        assertTrue(DataExposureEngine.massAssignmentCandidates("username=bob&password=hunter2").isEmpty());
    }

    @Test
    public void malformedJsonYieldsNoFindingsRatherThanThrowing() {
        assertTrue(DataExposureEngine.excessiveDataExposure("{\"ssn\":\"123\"").isEmpty());
    }

    @Test
    public void blankOrNullBodyYieldsNoFindings() {
        assertTrue(DataExposureEngine.excessiveDataExposure(null).isEmpty());
        assertTrue(DataExposureEngine.excessiveDataExposure("").isEmpty());
        assertTrue(DataExposureEngine.excessiveDataExposure("   ").isEmpty());
    }

    @Test
    public void topLevelJsonArrayIsWalkedToo() {
        String body = "[{\"id\":1,\"credit_card\":\"4111111111111111\"}]";
        List<DataExposureEngine.Field> fields = DataExposureEngine.excessiveDataExposure(body);

        assertEquals(1, fields.size());
        assertEquals("$[0].credit_card", fields.get(0).path());
    }

    @Test
    public void longValuePreviewIsTruncated() {
        String longValue = "x".repeat(100);
        String body = "{\"api_key\":\"" + longValue + "\"}";
        List<DataExposureEngine.Field> fields = DataExposureEngine.excessiveDataExposure(body);

        assertEquals(1, fields.size());
        assertTrue(fields.get(0).valuePreview().length() <= 60);
        assertTrue(fields.get(0).valuePreview().endsWith("..."));
    }
}
