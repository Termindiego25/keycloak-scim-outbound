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
        final String given    = esc(nvl(user != null ? user.getFirstName()  : null));
        final String family   = esc(nvl(user != null ? user.getLastName()   : null));
        final String email    = esc(nvl(user != null ? user.getEmail()      : null));
        final String uname    = esc(nvl(scimUserName));
        final String active   = (user != null && user.isEnabled()) ? "true" : "false";

        return """
            {
              "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
              "userName": "%s",
              "name": { "givenName": "%s", "familyName": "%s" },
              "emails": [ { "value": "%s", "type": "work", "primary": true } ],
              "active": %s
            }
            """.formatted(uname, given, family, email, active);
    }

    /** Build SCIM PatchOp JSON for PATCH /Users/{id}. */
    public static String buildPatchUser(UserModel user) {
        final String given  = esc(nvl(user != null ? user.getFirstName() : null));
        final String family = esc(nvl(user != null ? user.getLastName()  : null));
        final String email  = esc(nvl(user != null ? user.getEmail()     : null));
        final String active = (user != null && user.isEnabled()) ? "true" : "false";

        return """
            {
              "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
              "Operations": [
                {"op":"replace","path":"name.givenName","value":"%s"},
                {"op":"replace","path":"name.familyName","value":"%s"},
                {"op":"replace","path":"emails[primary eq true].value","value":"%s"},
                {"op":"replace","path":"active","value":%s}
              ]
            }
            """.formatted(given, family, email, active);
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

    /** Minimal JSON escape for string values. */
    public static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    /** Null-to-empty helper. */
    public static String nvl(String s) {
        return (s == null) ? "" : s;
    }
}