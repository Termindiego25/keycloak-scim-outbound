package es.diegosr.keycloak_scim_outbound.util;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Area 1 -- PATCH JSON generation.
 * Pure unit tests: no mocks, no Keycloak session needed.
 * ScimMapper is stateless and all methods are static.
 */
class ScimMapperTest {

    // -------------------------------------------------------------------------
    // Group member add
    // -------------------------------------------------------------------------

    @Test
    void add_containsCorrectOpPathAndValueArray() {
        String json = ScimMapper.buildGroupMemberPatch("add", "scim-user-1");

        assertTrue(json.contains("\"op\":\"add\""));
        assertTrue(json.contains("\"path\":\"members\""));
        assertTrue(json.contains("\"value\":[{\"value\":\"scim-user-1\"}]"));
        assertTrue(json.contains("urn:ietf:params:scim:api:messages:2.0:PatchOp"));
    }

    @Test
    void add_removeFormIsIgnored() {
        String rfcForm = ScimMapper.buildGroupMemberPatch(
                "add", "id-1", ScimMapper.REMOVE_FORM_RFC_PATH_FILTER);
        String nonRfcForm = ScimMapper.buildGroupMemberPatch(
                "add", "id-1", ScimMapper.REMOVE_FORM_NON_RFC_VALUE_ARRAY);

        assertEquals(rfcForm, nonRfcForm);
    }

    // -------------------------------------------------------------------------
    // Group member remove -- RFC 7644 path filter (default)
    // -------------------------------------------------------------------------

    @Test
    void remove_rfcPathFilter_usesFilterInPath_noValueArray() {
        String json = ScimMapper.buildGroupMemberPatch(
                "remove", "scim-user-2", ScimMapper.REMOVE_FORM_RFC_PATH_FILTER);

        assertTrue(json.contains("\"op\":\"remove\""));
        assertTrue(json.contains("members[value eq"));
        assertTrue(json.contains("scim-user-2"));
        assertFalse(json.contains("\"value\":["));
    }

    @Test
    void remove_defaultOverload_matchesExplicitRfcForm() {
        String explicit = ScimMapper.buildGroupMemberPatch(
                "remove", "scim-user-3", ScimMapper.REMOVE_FORM_RFC_PATH_FILTER);
        String defaultForm = ScimMapper.buildGroupMemberPatch("remove", "scim-user-3");

        assertEquals(explicit, defaultForm);
    }

    // -------------------------------------------------------------------------
    // Group member remove -- non-RFC value array
    // -------------------------------------------------------------------------

    @Test
    void remove_nonRfcValueArray_pathMembersWithValueArray() {
        String json = ScimMapper.buildGroupMemberPatch(
                "remove", "scim-user-4", ScimMapper.REMOVE_FORM_NON_RFC_VALUE_ARRAY);

        assertTrue(json.contains("\"op\":\"remove\""));
        assertTrue(json.contains("\"path\":\"members\""));
        assertTrue(json.contains("\"value\":[{\"value\":\"scim-user-4\"}]"));
    }

    // -------------------------------------------------------------------------
    // Group member replace
    // -------------------------------------------------------------------------

    @Test
    void replace_multipleMembers_allIdsPresent() {
        String json = ScimMapper.buildGroupMemberReplace(List.of("id-a", "id-b", "id-c"));

        assertTrue(json.contains("\"op\":\"replace\""));
        assertTrue(json.contains("\"path\":\"members\""));
        assertTrue(json.contains("\"value\":\"id-a\""));
        assertTrue(json.contains("\"value\":\"id-b\""));
        assertTrue(json.contains("\"value\":\"id-c\""));
    }

    @Test
    void replace_emptyList_producesEmptyValueArray() {
        String json = ScimMapper.buildGroupMemberReplace(List.of());

        assertTrue(json.contains("\"op\":\"replace\""));
        assertTrue(json.contains("\"value\":[]"));
    }

    // -------------------------------------------------------------------------
    // Create group
    // -------------------------------------------------------------------------

    @Test
    void createGroup_containsSchemaExternalIdAndDisplayName() {
        String json = ScimMapper.buildCreateGroup("Engineering", "kc-group-uuid-1");

        assertTrue(json.contains("urn:ietf:params:scim:schemas:core:2.0:Group"));
        assertTrue(json.contains("\"externalId\": \"kc-group-uuid-1\""));
        assertTrue(json.contains("\"displayName\": \"Engineering\""));
    }

    // -------------------------------------------------------------------------
    // Special characters in IDs
    // -------------------------------------------------------------------------

    @Test
    void add_specialCharsInMemberId_escapedCorrectly() {
        String id = "id-with-\"quote\"-and-\\backslash";
        String json = ScimMapper.buildGroupMemberPatch("add", id);

        assertFalse(json.contains("\"value\":\"" + id + "\""),
                "raw unescaped ID must not appear verbatim");
        assertTrue(json.contains("\\\"quote\\\""), "double-quote must be escaped");
        assertTrue(json.contains("\\\\backslash"), "backslash must be escaped");
    }

    @Test
    void replace_specialCharsInId_escapedCorrectly() {
        String id = "id\\with\"special";
        String json = ScimMapper.buildGroupMemberReplace(List.of(id));

        assertFalse(json.contains("\"value\":\"" + id + "\""));
        assertTrue(json.contains("\\\\with"));
        assertTrue(json.contains("\\\"special"));
    }

    // -------------------------------------------------------------------------
    // Deactivate patch
    // -------------------------------------------------------------------------

    @Test
    void deactivatePatch_singleReplaceActiveFalse() {
        String json = ScimMapper.buildDeactivatePatch();

        assertTrue(json.contains("\"op\":\"replace\""));
        assertTrue(json.contains("\"path\":\"active\""));
        assertTrue(json.contains("\"value\":false"));
        assertEquals(1, countOccurrences(json, "\"op\":"),
                "must contain exactly one operation");
    }

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    private static int countOccurrences(String text, String sub) {
        int count = 0;
        int idx = 0;
        while ((idx = text.indexOf(sub, idx)) >= 0) {
            count++;
            idx += sub.length();
        }
        return count;
    }
}
