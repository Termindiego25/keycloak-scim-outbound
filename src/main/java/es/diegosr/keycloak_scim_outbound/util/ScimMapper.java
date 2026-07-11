package es.diegosr.keycloak_scim_outbound.util;

import org.keycloak.models.UserModel;

import java.util.List;

/**
 * Builds SCIM v2 User payloads from Keycloak's UserModel.
 * Keep all string escaping / normalization here.
 */
public final class ScimMapper {

    private ScimMapper() {}

    /**
     * Group member remove form options (CFG_GROUP_MEMBER_REMOVE_FORM).
     *
     * RFC_PATH_FILTER -- RFC 7644 path filter:
     *   {"op":"remove","path":"members[value eq \"<id>\"]"}
     *   Spec-compliant; some servers do not accept it without a value field.
     *
     * NON_RFC_VALUE_ARRAY -- Non-RFC value array:
     *   {"op":"remove","path":"members","value":[{"value":"<id>"}]}
     *   Not mandated by RFC 7644 for removes but accepted by servers that
     *   require a value field on every operation (e.g. this deployment's target).
     */
    public static final String REMOVE_FORM_RFC_PATH_FILTER    = "RFC 7644 path filter";
    public static final String REMOVE_FORM_NON_RFC_VALUE_ARRAY = "Non-RFC value array";

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

    /** Build SCIM Group JSON for POST /Groups. externalId should be the Keycloak group ID. */
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
     * Build PatchOp to add or remove a single member from a SCIM group.
     *
     * The "add" operation always uses the standard path+value form (RFC 7644 s3.5.2):
     *   {"op":"add","path":"members","value":[{"value":"<id>"}]}
     *
     * The "remove" operation form is controlled by the removeForm parameter:
     *
     *   REMOVE_FORM_RFC_PATH_FILTER (default, spec-compliant):
     *     {"op":"remove","path":"members[value eq \"<id>\"]"}
     *
     *   REMOVE_FORM_NON_RFC_VALUE_ARRAY (for servers that require a value field on removes):
     *     {"op":"remove","path":"members","value":[{"value":"<id>"}]}
     *
     * Pass ScimTargetProviderFactory.get(target, CFG_GROUP_MEMBER_REMOVE_FORM,
     * REMOVE_FORM_RFC_PATH_FILTER) as removeForm.
     *
     * @param op         "add" or "remove"
     * @param memberId   SCIM user id of the member
     * @param removeForm one of REMOVE_FORM_RFC_PATH_FILTER or REMOVE_FORM_NON_RFC_VALUE_ARRAY;
     *                   ignored when op is "add"
     */
    public static String buildGroupMemberPatch(String op, String memberId, String removeForm) {
        final String escapedId = esc(nvl(memberId));
        if ("remove".equals(op)) {
            if (REMOVE_FORM_NON_RFC_VALUE_ARRAY.equals(removeForm)) {
                // Non-RFC value array form: servers that reject path-filter removes
                // without a value field accept this form instead.
                return "{\n"
                     + "  \"schemas\": [\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\n"
                     + "  \"Operations\": [\n"
                     + "    {\"op\":\"remove\",\"path\":\"members\",\"value\":[{\"value\":\""
                     + escapedId
                     + "\"}]}\n"
                     + "  ]\n"
                     + "}\n";
            }
            // RFC 7644 path filter form (default)
            return "{\n"
                 + "  \"schemas\": [\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\n"
                 + "  \"Operations\": [\n"
                 + "    {\"op\":\"remove\",\"path\":\"members[value eq \\\""
                 + escapedId
                 + "\\\"]\"}\\n"
                 + "  ]\n"
                 + "}\n";
        }
        return """
            {
              "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
              "Operations": [
                {"op":"add","path":"members","value":[{"value":"%s"}]}
              ]
            }
            """.formatted(escapedId);
    }

    /**
     * Backward-compatible overload: uses RFC 7644 path filter form for removes.
     * Retained for call sites that do not have access to a ComponentModel
     * (e.g. ScimEventListenerProvider). New call sites should use the three-argument
     * overload and pass the configured removeForm.
     */
    public static String buildGroupMemberPatch(String op, String memberId) {
        return buildGroupMemberPatch(op, memberId, REMOVE_FORM_RFC_PATH_FILTER);
    }

    /**
     * Builds a SCIM PATCH request body that replaces the entire members list of a group
     * with the provided set of SCIM user IDs. Uses op=replace on the members attribute.
     * RFC 7644 ss3.5.2.
     *
     * An empty scimUserIds list produces a replace with an empty array (clears all members).
     *
     * @param scimUserIds list of SCIM user IDs (the "value" field of each member entry)
     */
    public static String buildGroupMemberReplace(List<String> scimUserIds) {
        StringBuilder valueArray = new StringBuilder("[");
        if (scimUserIds != null && !scimUserIds.isEmpty()) {
            for (int i = 0; i < scimUserIds.size(); i++) {
                if (i > 0) valueArray.append(",");
                valueArray.append("{\"value\":\"").append(esc(nvl(scimUserIds.get(i)))).append("\"}");
            }
        }
        valueArray.append("]");

        return "{\n"
             + "  \"schemas\": [\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\n"
             + "  \"Operations\": [\n"
             + "    {\"op\":\"replace\",\"path\":\"members\",\"value\":" + valueArray + "}\n"
             + "  ]\n"
             + "}\n";
    }

    /** Build PatchOp to rename a SCIM group (replace displayName). */
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

    /* ===== helpers ===== */

    /** JSON escape for string values. */
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

    /** Null-to-empty helper. */
    public static String nvl(String s) {
        return (s == null) ? "" : s;
    }
}
