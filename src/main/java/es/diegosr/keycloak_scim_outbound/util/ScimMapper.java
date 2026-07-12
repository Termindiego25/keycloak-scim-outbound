package es.diegosr.keycloak_scim_outbound.util;

import org.keycloak.models.UserModel;

import java.util.List;

/**
 * Builds SCIM v2 payloads (Users and Groups) from Keycloak models.
 *
 * All JSON is assembled via Java text blocks. No raw string concatenation is
 * used to construct JSON structure -- only %s slots inside text blocks, or a
 * StringBuilder for variable-length Operations / value arrays.
 */
public final class ScimMapper {

    private ScimMapper() {}

    /**
     * Group member remove form options (CFG_GROUP_MEMBER_REMOVE_FORM).
     *
     * REMOVE_FORM_RFC_PATH_FILTER (default, spec-compliant):
     *   {"op":"remove","path":"members[value eq \"<id>\"]"}
     *   RFC 7644 s3.5.2. Some servers reject this without a value field.
     *
     * REMOVE_FORM_NON_RFC_VALUE_ARRAY:
     *   {"op":"remove","path":"members","value":[{"value":"<id>"}]}
     *   Not mandated by RFC 7644 for removes, but required by servers that
     *   validate the presence of a value field on every operation.
     */
    public static final String REMOVE_FORM_RFC_PATH_FILTER     = "RFC 7644 path filter";
    public static final String REMOVE_FORM_NON_RFC_VALUE_ARRAY = "Non-RFC value array";

    // =========================================================================
    // Users
    // =========================================================================

    /** Backward-compatible wrapper: uses Keycloak username as SCIM userName. */
    public static String buildCreateUser(UserModel user) {
        String fallback = user != null ? user.getUsername() : "";
        return buildCreateUser(user, fallback);
    }

    /** Build SCIM User JSON for POST /Users with an explicit SCIM userName. */
    public static String buildCreateUser(UserModel user, String scimUserName) {
        final String given  = esc(nvl(user != null ? user.getFirstName() : null));
        final String family = esc(nvl(user != null ? user.getLastName()  : null));
        final String email  = esc(nvl(user != null ? user.getEmail()     : null));
        final String uname  = esc(nvl(scimUserName));
        final String extId  = esc(nvl(user != null ? user.getId()        : null));
        final String active = (user != null && user.isEnabled()) ? "true" : "false";

        return """
                {
                  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                  "externalId": "%s",
                  "userName": "%s",
                  "name": { "givenName": "%s", "familyName": "%s" },
                  "emails": [ { "value": "%s", "type": "work", "primary": true } ],
                  "active": %s
                }
                """.formatted(extId, uname, given, family, email, active);
    }

    /** Backward-compatible wrapper: PATCH without touching externalId. */
    public static String buildPatchUser(UserModel user) {
        return buildPatchUser(user, null);
    }

    /**
     * Build SCIM PatchOp JSON for PATCH /Users/{id}.
     *
     * When externalId is non-null, an "add" op is prepended so already-provisioned
     * users that lack an externalId get one set on the next update or upsert.
     *
     * The Operations list is variable-length, so it is assembled with a StringBuilder.
     * The surrounding envelope uses a text block with a %s slot.
     */
    public static String buildPatchUser(UserModel user, String externalId) {
        final String given  = esc(nvl(user != null ? user.getFirstName() : null));
        final String family = esc(nvl(user != null ? user.getLastName()  : null));
        final String email  = esc(nvl(user != null ? user.getEmail()     : null));
        final String active = (user != null && user.isEnabled()) ? "true" : "false";
        final String extId  = esc(nvl(externalId));

        StringBuilder ops = new StringBuilder();
        if (!extId.isEmpty()) {
            ops.append("    {\"op\":\"add\",\"path\":\"externalId\",\"value\":\"")
               .append(extId).append("\"},\n");
        }
        ops.append("    {\"op\":\"replace\",\"path\":\"name.givenName\",\"value\":\"")
           .append(given).append("\"},\n");
        ops.append("    {\"op\":\"replace\",\"path\":\"name.familyName\",\"value\":\"")
           .append(family).append("\"},\n");
        ops.append("    {\"op\":\"replace\",\"path\":\"emails[primary eq true].value\",\"value\":\"")
           .append(email).append("\"},\n");
        ops.append("    {\"op\":\"replace\",\"path\":\"active\",\"value\":")
           .append(active).append("}");

        return """
                {
                  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                  "Operations": [
                %s
                  ]
                }
                """.formatted(ops);
    }

    /** Build SCIM PatchOp to deactivate a user (set active=false). */
    public static String buildDeactivatePatch() {
        return """
                {
                  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                  "Operations": [
                    {"op":"replace","path":"active","value":false}
                  ]
                }
                """;
    }

    // =========================================================================
    // Groups
    // =========================================================================

    /**
     * Build SCIM Group JSON for POST /Groups.
     * externalId should be the Keycloak group UUID.
     */
    public static String buildCreateGroup(String displayName, String externalId) {
        final String name  = esc(nvl(displayName));
        final String extId = esc(nvl(externalId));
        return """
                {
                  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                  "externalId": "%s",
                  "displayName": "%s"
                }
                """.formatted(extId, name);
    }

    /**
     * Build a SCIM PatchOp that adds or removes a single member from a group.
     *
     * The "add" operation always uses the standard path+value form (RFC 7644 s3.5.2):
     *   {"op":"add","path":"members","value":[{"value":"<id>"}]}
     *
     * The "remove" operation form is controlled by removeForm:
     *
     *   REMOVE_FORM_RFC_PATH_FILTER (default):
     *     {"op":"remove","path":"members[value eq \"<id>\"]"}
     *
     *   REMOVE_FORM_NON_RFC_VALUE_ARRAY:
     *     {"op":"remove","path":"members","value":[{"value":"<id>"}]}
     *
     * @param op         "add" or "remove"
     * @param memberId   SCIM user id of the member
     * @param removeForm one of the REMOVE_FORM_* constants; ignored when op is "add"
     */
    public static String buildGroupMemberPatch(String op, String memberId, String removeForm) {
        final String id = esc(nvl(memberId));

        if ("remove".equals(op)) {
            if (REMOVE_FORM_NON_RFC_VALUE_ARRAY.equals(removeForm)) {
                return """
                        {
                          "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                          "Operations": [
                            {"op":"remove","path":"members","value":[{"value":"%s"}]}
                          ]
                        }
                        """.formatted(id);
            }
            // RFC 7644 path filter form (default).
            // The escaped quote inside the filter is a JSON string escape (\"), not a
            // Java source escape -- text blocks handle the surrounding quoting cleanly.
            return """
                    {
                      "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                      "Operations": [
                        {"op":"remove","path":"members[value eq \\"%s\\"]"}
                      ]
                    }
                    """.formatted(id);
        }

        // "add"
        return """
                {
                  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                  "Operations": [
                    {"op":"add","path":"members","value":[{"value":"%s"}]}
                  ]
                }
                """.formatted(id);
    }

    /**
     * Backward-compatible overload: uses RFC 7644 path filter form for removes.
     * Retained for call sites that do not have access to a ComponentModel.
     * New call sites should use the three-argument overload and pass the configured
     * removeForm from CFG_GROUP_MEMBER_REMOVE_FORM.
     */
    public static String buildGroupMemberPatch(String op, String memberId) {
        return buildGroupMemberPatch(op, memberId, REMOVE_FORM_RFC_PATH_FILTER);
    }

    /**
     * Build a SCIM PatchOp that replaces the entire members list of a group.
     * Uses op=replace on the members attribute (RFC 7644 s3.5.2).
     * An empty list produces a replace with an empty array, clearing all members.
     *
     * The value array is variable-length so it is assembled with a StringBuilder.
     * The surrounding envelope uses a text block with a %s slot.
     *
     * @param scimUserIds list of SCIM user IDs (the "value" field of each member entry)
     */
    public static String buildGroupMemberReplace(List<String> scimUserIds) {
        StringBuilder arr = new StringBuilder("[");
        if (scimUserIds != null) {
            for (int i = 0; i < scimUserIds.size(); i++) {
                if (i > 0) arr.append(",");
                arr.append("{\"value\":\"")
                   .append(esc(nvl(scimUserIds.get(i))))
                   .append("\"}");
            }
        }
        arr.append("]");

        return """
                {
                  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                  "Operations": [
                    {"op":"replace","path":"members","value":%s}
                  ]
                }
                """.formatted(arr);
    }

    /** Build a SCIM PatchOp that renames a group (replace displayName). */
    public static String buildPatchGroupDisplayName(String newDisplayName) {
        final String name = esc(nvl(newDisplayName));
        return """
                {
                  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                  "Operations": [
                    {"op":"replace","path":"displayName","value":"%s"}
                  ]
                }
                """.formatted(name);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /** JSON-escape a string value. Handles all characters required by RFC 8259. */
    public static String esc(String s) {
        if (s == null) return "";
        StringBuilder out = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"'  -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }

    /** Converts null to empty string. */
    public static String nvl(String s) {
        return (s == null) ? "" : s;
    }
}
