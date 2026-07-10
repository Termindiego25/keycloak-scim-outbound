package es.diegosr.keycloak_scim_outbound.ldapsync;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * State record for SCIM /Groups LDAP sync. Stored as multi-valued attributes on
 * GroupModel (Keycloak local group attributes).
 *
 * Two attributes per group:
 *   scimGroupSync.membershipState  -- full state list; one JSON value per (componentId, userId) pair
 *   scimGroupSync.pending          -- work-queue flag; one value "<componentId>:1" per target
 *                                     that has at least one un-SENT entry for this group
 *
 * Serialized format per value:
 *   {"c":"<componentId>","u":"<userId>","s":"<STATE>"}
 *
 * State meanings:
 *   NEW_ADDED   -- user gained membership in this group for this target; SCIM PATCH add pending
 *   SENT        -- membership add was successfully pushed; no action needed
 *   NEW_DELETED -- user lost membership; SCIM PATCH remove pending
 *
 * When a NEW_DELETED push succeeds, the entry is removed entirely (no "sent" state left).
 *
 * Groups are realm-local, not federated storage, so group attributes can be written
 * directly via GroupModel.setAttribute(...) without going through UserStoragePrivateUtil.
 *
 * Parallel to MembershipState (which tracks /Users LDAP sync on UserModel).
 */
public record GroupMembershipState(String componentId, String userId, State state) {

    public static final String ATTRIBUTE_NAME         = "scimGroupSync.membershipState";
    public static final String PENDING_ATTRIBUTE_NAME = "scimGroupSync.pending";

    public enum State { NEW_ADDED, NEW_DELETED, SENT }

    /**
     * Serialize to JSON value stored in the group attribute.
     * Format: {"c":"<componentId>","u":"<userId>","s":"<STATE>"}
     */
    public String toValue() {
        return "{\"c\":\"" + esc(componentId) + "\",\"u\":\"" + esc(userId) + "\",\"s\":\"" + state.name() + "\"}";
    }

    /**
     * Returns the pending-flag sentinel value for the given componentId.
     * Written to PENDING_ATTRIBUTE_NAME to mark that a target has un-SENT entries on this group.
     */
    public static String pendingValue(String componentId) {
        return componentId + ":1";
    }

    /**
     * Parse a single attribute value string into a GroupMembershipState, or empty if malformed.
     */
    public static Optional<GroupMembershipState> parse(String value) {
        if (value == null || value.isBlank()) return Optional.empty();
        try {
            String c = extractJsonField(value, "c");
            String u = extractJsonField(value, "u");
            String s = extractJsonField(value, "s");
            if (c == null || u == null || s == null) return Optional.empty();
            State state = State.valueOf(s);
            return Optional.of(new GroupMembershipState(c, u, state));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    /**
     * Find the GroupMembershipState entry for the given componentId and userId in a list
     * of raw attribute values, or empty if none exists.
     */
    public static Optional<GroupMembershipState> findForComponent(List<String> values,
                                                                   String componentId,
                                                                   String userId) {
        for (String raw : values) {
            Optional<GroupMembershipState> parsed = parse(raw);
            if (parsed.isPresent()
                    && parsed.get().componentId().equals(componentId)
                    && parsed.get().userId().equals(userId)) {
                return parsed;
            }
        }
        return Optional.empty();
    }

    /**
     * Return a copy of the values list with all entries for the given componentId removed.
     * Used during full-sync cleanup.
     */
    public static List<String> removeAllForComponent(List<String> values, String componentId) {
        List<String> result = new ArrayList<>();
        for (String raw : values) {
            Optional<GroupMembershipState> parsed = parse(raw);
            if (parsed.isEmpty() || !parsed.get().componentId().equals(componentId)) {
                result.add(raw);
            }
        }
        return result;
    }

    /* ===== minimal JSON helpers (no external library) ===== */

    /** Extract the string value of a single-level JSON string field by key. Returns null if not found. */
    private static String extractJsonField(String json, String key) {
        String search = "\"" + key + "\":\"";
        int start = json.indexOf(search);
        if (start < 0) return null;
        start += search.length();
        int end = start;
        while (end < json.length()) {
            char c = json.charAt(end);
            if (c == '\\') {
                end += 2;
                continue;
            }
            if (c == '"') break;
            end++;
        }
        if (end >= json.length()) return null;
        return unescape(json.substring(start, end));
    }

    /** Minimal JSON string escaper (handles the characters that appear in KC IDs and state names). */
    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default   -> sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Minimal JSON string unescaper for the subset produced by esc(). */
    private static String unescape(String s) {
        if (s == null || !s.contains("\\")) return s;
        StringBuilder sb = new StringBuilder(s.length());
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char next = s.charAt(i + 1);
                switch (next) {
                    case '"'  -> { sb.append('"');  i += 2; }
                    case '\\' -> { sb.append('\\'); i += 2; }
                    case 'n'  -> { sb.append('\n'); i += 2; }
                    case 'r'  -> { sb.append('\r'); i += 2; }
                    case 't'  -> { sb.append('\t'); i += 2; }
                    default   -> { sb.append(c); i++; }
                }
            } else {
                sb.append(c);
                i++;
            }
        }
        return sb.toString();
    }
}
