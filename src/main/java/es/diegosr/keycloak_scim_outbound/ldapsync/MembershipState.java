package es.diegosr.keycloak_scim_outbound.ldapsync;

import java.util.List;
import java.util.Optional;

/**
 * Represents one entry of the multi-valued user attribute
 * "ldapSyncNotifier.filterGroupMembership".
 *
 * Serialized format per value (JSON):
 *   {"c":"<componentId>","g":"<groupId>","s":"<STATE>"}
 *
 * where STATE is one of NEW_ADDED, NEW_DELETED, SENT.
 *
 * Using the group's stable ID (rather than its display name) means the entry
 * survives group renames without becoming stale. JSON encoding means no field
 * can ever break the parser regardless of what characters appear in the IDs.
 *
 * - NEW_ADDED  : user gained membership in the target's filter group; SCIM push pending.
 * - SENT       : membership add was successfully pushed to SCIM; no action needed.
 * - NEW_DELETED: user lost membership in the target's filter group; SCIM deprovision pending.
 *   (once successfully pushed, the entry is removed entirely -- there is no
 *    "removed and sent" state, since there's nothing left to track.)
 */
public record MembershipState(String componentId, String groupId, State state) {

    public static final String ATTRIBUTE_NAME = "ldapSyncNotifier.filterGroupMembership";

    /**
     * Lightweight multi-valued "work queue" attribute, separate from ATTRIBUTE_NAME above.
     * Each value is "<componentId>:1", present exactly when that user has at least one
     * un-SENT (NEW_ADDED/NEW_DELETED) entry for that SCIM target in ATTRIBUTE_NAME.
     *
     * This exists purely so ScimMembershipSync can find "users with pending work" via a
     * single indexed searchForUserByUserAttributeStream(realm, PENDING_ATTRIBUTE_NAME, ...)
     * call per target, instead of iterating every user in the realm (which does not scale --
     * e.g. 941 users -- and was the original performance problem).
     *
     * Lifecycle:
     *   - SET by LdapSyncNotifierMapper whenever it marks a NEW_ADDED/NEW_DELETED transition
     *     for a given (user, componentId) pair.
     *   - CLEARED by ScimMembershipSync once that user has no more un-SENT entries for that
     *     componentId (i.e. the pending push/deprovision succeeded).
     */
    public static final String PENDING_ATTRIBUTE_NAME = "ldapSyncNotifier.pending";

    public enum State {
        NEW_ADDED, NEW_DELETED, SENT
    }

    /**
     * Serializes this entry to a JSON string.
     * All three fields (componentId, groupId, state name) are safe to embed in JSON
     * regardless of their content -- no delimiter-collision risk.
     */
    public String toValue() {
        return "{\"c\":" + jsonString(componentId)
                + ",\"g\":" + jsonString(groupId)
                + ",\"s\":" + jsonString(state.name())
                + "}";
    }

    /**
     * Value to add to PENDING_ATTRIBUTE_NAME to flag that componentId has pending work
     * for a user.
     */
    public static String pendingValue(String componentId) {
        return componentId + ":1";
    }

    public static Optional<MembershipState> parse(String value) {
        if (value == null || value.isBlank()) return Optional.empty();
        try {
            String c = extractJsonString(value, "c");
            String g = extractJsonString(value, "g");
            String s = extractJsonString(value, "s");
            if (c == null || g == null || s == null) return Optional.empty();
            return Optional.of(new MembershipState(c, g, State.valueOf(s)));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    public static Optional<MembershipState> findForComponent(List<String> values, String componentId) {
        return values.stream()
                .map(MembershipState::parse)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .filter(s -> s.componentId().equals(componentId))
                .findFirst();
    }

    // -------------------------------------------------------------------------
    // Minimal JSON helpers -- avoids pulling in a JSON library dependency just
    // for this small record. Only handles the exact structure we write ourselves.
    // -------------------------------------------------------------------------

    /** Wraps a string value in JSON double-quotes, escaping backslash and double-quote. */
    private static String jsonString(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    /**
     * Extracts the string value for a given key from a JSON object of the form
     * {"c":"...","g":"...","s":"..."}.
     * Returns null if the key is not found or the value is not a quoted string.
     * This is intentionally minimal -- it only handles the exact format we produce
     * in toValue() and is not a general-purpose JSON parser.
     */
    private static String extractJsonString(String json, String key) {
        String needle = "\"" + key + "\":\"";
        int start = json.indexOf(needle);
        if (start < 0) return null;
        start += needle.length();
        StringBuilder sb = new StringBuilder();
        boolean escaped = false;
        for (int i = start; i < json.length(); i++) {
            char ch = json.charAt(i);
            if (escaped) {
                sb.append(ch);
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                return sb.toString();
            } else {
                sb.append(ch);
            }
        }
        return null; // unterminated string
    }
}
