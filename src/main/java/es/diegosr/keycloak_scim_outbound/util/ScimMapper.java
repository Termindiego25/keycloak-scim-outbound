package es.diegosr.keycloak_scim_outbound.util;

import org.keycloak.models.UserModel;

/**
 * Builds SCIM v2 User payloads from Keycloak's UserModel.
 * Keep all string escaping / normalization here.
 */
public final class ScimMapper {

    private ScimMapper() {}

    /** Backward-compatible wrapper: uses Keycloak username if no explicit SCIM userName is provided. */
    public static String buildCreateUser(UserModel user) {
        String fallback = user != null ? user.getUsername() : "";
        return buildCreateUser(user, fallback);
    }

    /** Build SCIM User JSON for POST /Users with explicit SCIM userName (strategy-based). */
    public static String buildCreateUser(UserModel user, String scimUserName) {
        final String given     = esc(nvl(user != null ? user.getFirstName()  : null));
        final String family    = esc(nvl(user != null ? user.getLastName()   : null));
        final String email     = esc(nvl(user != null ? user.getEmail()      : null));
        final String uname     = esc(nvl(scimUserName));
        final String extId     = esc(nvl(user != null ? user.getId()         : null));
        final String active    = (user != null && user.isEnabled()) ? "true" : "false";

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
     * When {@code externalId} is provided, an "add" op is included so already-provisioned
     * users that lack an externalId get one set on update/upsert.
     */
    public static String buildPatchUser(UserModel user, String externalId) {
        final String given  = esc(nvl(user != null ? user.getFirstName() : null));
        final String family = esc(nvl(user != null ? user.getLastName()  : null));
        final String email  = esc(nvl(user != null ? user.getEmail()     : null));
        final String active = (user != null && user.isEnabled()) ? "true" : "false";
        final String extId  = esc(nvl(externalId));

        StringBuilder ops = new StringBuilder();
        if (!extId.isEmpty()) {
            ops.append("    {\"op\":\"add\",\"path\":\"externalId\",\"value\":\"").append(extId).append("\"},\n");
        }
        ops.append("    {\"op\":\"replace\",\"path\":\"name.givenName\",\"value\":\"").append(given).append("\"},\n");
        ops.append("    {\"op\":\"replace\",\"path\":\"name.familyName\",\"value\":\"").append(family).append("\"},\n");
        ops.append("    {\"op\":\"replace\",\"path\":\"emails[primary eq true].value\",\"value\":\"").append(email).append("\"},\n");
        ops.append("    {\"op\":\"replace\",\"path\":\"active\",\"value\":").append(active).append("}");

        return "{\n"
             + "  \"schemas\": [\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\n"
             + "  \"Operations\": [\n"
             + ops
             + "\n  ]\n}\n";
    }

    /** Patch to deactivate (active=false). */
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

    /* ===== helpers ===== */

    /** JSON escape for string values. */
    public static String esc(String s) {
        if (s == null) return "";
        StringBuilder out = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
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

    /** Null-to-empty helper. */
    public static String nvl(String s) {
        return (s == null) ? "" : s;
    }
}
