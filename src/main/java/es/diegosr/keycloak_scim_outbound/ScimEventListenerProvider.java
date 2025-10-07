package es.diegosr.keycloak_scim_outbound;

import es.diegosr.keycloak_scim_outbound.http.ScimClient;
import es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory;
import es.diegosr.keycloak_scim_outbound.util.ScimMapper;

import static es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory.*;

import org.keycloak.component.ComponentModel;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.*;

import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Event listener that pushes user lifecycle changes (create/update/delete)
 * to one or more SCIM targets configured via UI (User Federation component).
 *
 * Supports:
 *  - User events: REGISTER, UPDATE_PROFILE, UPDATE_EMAIL, UPDATE_CREDENTIAL(password), DELETE_ACCOUNT
 *  - Admin events: CREATE/UPDATE/DELETE on ResourceType.USER
 *  - Group membership events (ResourceType.GROUP_MEMBERSHIP) to drive provisioning when filterGroup is set
 */
public class ScimEventListenerProvider implements EventListenerProvider {
    private final KeycloakSession session;

    private static final Set<EventType> USER_EVENTS_OF_INTEREST = EnumSet.of(
            EventType.REGISTER,
            EventType.UPDATE_PROFILE,
            EventType.UPDATE_EMAIL,
            EventType.UPDATE_CREDENTIAL,
            EventType.DELETE_ACCOUNT
    );

    /** Debounce map to avoid duplicated pushes when KC emits both user+admin events. */
    private final ConcurrentHashMap<String, Long> debounce = new ConcurrentHashMap<>();
    private static final long DEBOUNCE_MS = 2000;

    public ScimEventListenerProvider(KeycloakSession session) {
        this.session = session;
    }

    /* ===== User events ===== */
    @Override
    public void onEvent(Event event) {
        if (!USER_EVENTS_OF_INTEREST.contains(event.getType())) return;

        RealmModel realm = session.realms().getRealm(event.getRealmId());
        if (realm == null) return;

        UserModel user = session.users().getUserById(realm, event.getUserId());
        final String userId = (user != null) ? user.getId() : event.getUserId();
        final String username = (user != null) ? user.getUsername() : "(unknown)";

        switch (event.getType()) {
            case REGISTER -> dispatch("CREATE", realm, userId, username, user, event.getDetails());
            case UPDATE_PROFILE, UPDATE_EMAIL -> dispatch("UPDATE", realm, userId, username, user, event.getDetails());
            case UPDATE_CREDENTIAL -> {
                Map<String, String> d = event.getDetails();
                if (d != null && "password".equalsIgnoreCase(d.get("credential_type"))) {
                    dispatch("UPDATE", realm, userId, username, user, d);
                }
            }
            case DELETE_ACCOUNT -> dispatch("DELETE", realm, userId, username, user, event.getDetails());
            default -> {}
        }
    }

    /* ===== Admin events (users + group membership) ===== */
    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        if (adminEvent == null) return;

        // 1) MEMBERSHIP CHANGES FIRST
        if (adminEvent.getResourceType() == ResourceType.GROUP_MEMBERSHIP) {
            final RealmModel realm = session.realms().getRealm(adminEvent.getRealmId());
            if (realm == null) return;

            final String raw = adminEvent.getResourcePath(); // e.g. "users/{uid}/groups/{gid}" o "groups/{gid}/members/{uid}"
            final String path = raw.startsWith("/") ? raw : "/" + raw;  // <-- NORMALIZACIÓN CLAVE

            // Patrones habituales:
            //  - /users/{userId}/groups/{groupId}
            //  - /groups/{groupId}/members/{userId}
            String userId  = extractSegmentAfter(path, "/users/");
            String groupId = extractSegmentAfter(path, "/groups/");

            // alternativo "groups/{gid}/members/{uid}"
            if (userId == null)  userId  = extractSegmentAfter(path, "/members/");
            if (groupId == null) groupId = extractSegmentAfter(path, "/groups/");

            if (userId == null || groupId == null) {
                logInfo("SCIM", "membership", "Cannot parse membership path: %s", raw);
                return;
            }

            final UserModel  user  = session.users().getUserById(realm, userId);
            final GroupModel group = session.groups().getGroupById(realm, groupId);
            final String groupName = (group != null ? group.getName() : null);
            final String username  = (user  != null ? user.getUsername() : "(unknown)");

            if (groupName == null) {
                logInfo("SCIM", "membership", "Group not found for id=%s (path=%s)", groupId, path);
                return;
            }

            // Para cada target SCIM del realm: actuar solo si su filterGroup coincide
            final List<ComponentModel> targets = realm.getComponentsStream()
                    .filter(c -> ScimTargetProviderFactory.ID.equals(c.getProviderId()))
                    .toList();

            for (ComponentModel t : targets) {
                final String cfgGroup = ScimTargetProviderFactory.get(t, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
                if (cfgGroup == null || cfgGroup.isBlank() || !cfgGroup.equals(groupName)) continue;

                final String base  = ScimTargetProviderFactory.get(t, ScimTargetProviderFactory.CFG_BASE_URL, null);
                final String token = ScimTargetProviderFactory.get(t, ScimTargetProviderFactory.CFG_TOKEN, null);
                if (base == null || token == null) {
                    logErr("SCIM", t.getName(), "Incomplete configuration (baseUrl/token). Skipping membership event.");
                    continue;
                }

                final String scimUserName = computeScimUserName(t, user, username);
                if (scimUserName == null || scimUserName.isBlank()) {
                    logErr("SCIM", t.getName(), "Cannot resolve SCIM userName for user=%s. Skipping membership event.", username);
                    continue;
                }

                final ScimClient client = new ScimClient(base, token);
                final OperationType op  = adminEvent.getOperationType();
                final String debounceKey = "GM:" + realm.getId() + ":" + userId + ":" + groupId + ":" + op;
                final long now = java.time.Instant.now().toEpochMilli();
                final Long last = debounce.put(debounceKey, now);
                if (last != null && (now - last) < DEBOUNCE_MS) continue;

                try {
                    switch (op) {
                        case CREATE -> { // user ADDED to group
                            boolean changed = upsertUser(client, user, scimUserName);
                            logInfo("SCIM", t.getName(), "GROUP ADD user=%s group=%s -> %s",
                                    scimUserName, groupName, changed ? "OK" : "NO-OP");
                        }
                        case DELETE -> { // user REMOVED from group
                            deactivateUser(client, scimUserName);
                            logInfo("SCIM", t.getName(), "GROUP REMOVE user=%s group=%s -> OK",
                                    scimUserName, groupName);
                        }
                        default -> {
                            // ignore UPDATE/others
                        }
                    }
                } catch (Exception e) {
                    logErr("SCIM", t.getName(), "GROUP %s user=%s group=%s ERROR: %s",
                            op, scimUserName, groupName, e.getMessage());
                }
            }
            return; // membership handled
        }

        // 2) USER CRUD EVENTS
        if (adminEvent.getResourceType() == ResourceType.USER) {
            final RealmModel realm = session.realms().getRealm(adminEvent.getRealmId());
            if (realm == null) return;

            final String userId = extractUserId(adminEvent.getResourcePath());
            if (userId == null) return;

            final UserModel user = session.users().getUserById(realm, userId);
            final String username = (user != null) ? user.getUsername() : "(unknown)";

            final OperationType op = adminEvent.getOperationType();
            switch (op) {
                case CREATE -> dispatch("CREATE", realm, userId, username, user, null);
                case UPDATE -> dispatch("UPDATE", realm, userId, username, user, null);
                case DELETE -> dispatch("DELETE", realm, userId, username, user, null);
                default -> { /* ignore */ }
            }
        }
        // other resource types -> ignore
    }

    /* ===== Core dispatch ===== */

    private void dispatch(String action, RealmModel realm, String userId, String username, UserModel user, Map<String,String> details) {
        // Debounce to reduce double delivery (user event + admin event)
        String key = realm.getId() + ":" + action + ":" + userId;
        long now = Instant.now().toEpochMilli();
        Long last = debounce.put(key, now);
        if (last != null && (now - last) < DEBOUNCE_MS) return;

        List<ComponentModel> targets = realm.getComponentsStream()
                .filter(c -> ScimTargetProviderFactory.ID.equals(c.getProviderId()))
                .toList();

        for (ComponentModel t : targets) {
            handleTarget(t, action, realm, userId, username, user);
        }
    }

    private void handleTarget(ComponentModel t, String action, RealmModel realm, String userId, String username, UserModel user) {
        final String base   = get(t, CFG_BASE_URL, null);
        final String token  = get(t, CFG_TOKEN, null);
        final String group  = get(t, CFG_FILTER_GROUP, null);

        if (base == null || token == null) {
            logErr("SCIM", t.getName(), "Incomplete configuration (baseUrl/token). Skipping.");
            return;
        }

        final String scimUserName = computeScimUserName(t, user, username);
        if (scimUserName == null || scimUserName.isBlank()) {
            logErr("SCIM", t.getName(), "Could not resolve SCIM 'userName' for user=%s. Skipping.", username);
            return;
        }

        if (!"DELETE".equals(action) && group != null && !group.isBlank()) {
            if (user == null) {
                logInfo("SCIM", t.getName(), "User model not found; skipping due to group filter.");
                return;
            }
            boolean inGroup = user.getGroupsStream().anyMatch(g -> g.getName().equals(group));
            if (!inGroup) {
                logInfo("SCIM", t.getName(), "User %s does not belong to group '%s'. Skipping.", username, group);
                return;
            }
        }

        ScimClient client = new ScimClient(base, token);

        try {
            boolean changed = switch (action) {
                case "CREATE", "UPDATE" -> upsertUser(client, user, scimUserName);
                case "DELETE" -> { deactivateUser(client, scimUserName); yield true; }
                default -> false;
            };

            if (changed) {
                logInfo("SCIM", t.getName(), "%s targetUserName=%s realm=%s OK", action, scimUserName, realm.getName());
            } else {
                logInfo("SCIM", t.getName(), "%s targetUserName=%s realm=%s NO-OP (not found / not changed)", action, scimUserName, realm.getName());
            }
        } catch (Exception e) {
            logErr("SCIM", t.getName(), "%s targetUserName=%s ERROR: %s", action, scimUserName, e.getMessage());
        }
    }

    // Resolve SCIM userName from strategy
    private String computeScimUserName(ComponentModel t, UserModel user, String fallbackUsername) {
        String strategy = get(t, CFG_UNAME_STRATEGY, "username");
        logInfo("keycloak-scim-outbound", t.getName(), "Using userNameStrategy=%s", strategy);

        if (user == null) return fallbackUsername; // best-effort on deletes

        switch (strategy) {
            case "username":
                return user.getUsername();
            case "email":
                return nullIfBlank(user.getEmail());
            case "attribute":
                String attr = get(t, CFG_UNAME_ATTR, null);
                return attr == null ? null : nullIfBlank(user.getFirstAttribute(attr));
            default:
                return user.getUsername();
        }
    }

    private static String nullIfBlank(String s) { return (s == null || s.isBlank()) ? null : s; }

    /**
     * Returns true if we successfully created or patched the SCIM user.
     */
    private boolean upsertUser(ScimClient scim, UserModel user, String scimUserName) {
        if (user == null) return false;

        var existingId = scim.findUserIdByUserName(scimUserName);
        if (existingId.isEmpty()) {
            boolean created = scim.createUser(ScimMapper.buildCreateUser(user, scimUserName));
            if (created) return true;

            // Creation failed (likely 409). Re-resolve and PATCH.
            existingId = scim.findUserIdByUserName(scimUserName);
            return existingId.map(id -> scim.patchUser(id, ScimMapper.buildPatchUser(user))).orElse(false);
        } else {
            return scim.patchUser(existingId.get(), ScimMapper.buildPatchUser(user));
        }
    }

    private void deactivateUser(ScimClient scim, String scimUserName) {
        var existingId = scim.findUserIdByUserName(scimUserName);
        existingId.ifPresent(id -> scim.patchUser(id, ScimMapper.buildDeactivatePatch()));
    }

    private static String extractUserId(String resourcePath) {
        if (resourcePath == null) return null;
        String[] p = resourcePath.split("/");
        for (int i = 0; i < p.length - 1; i++) {
            if ("users".equals(p[i])) return p[i + 1];
        }
        return null;
    }

    private static String extractSegmentAfter(String path, String marker) {
        if (path == null) return null;
        int i = path.indexOf(marker);
        if (i < 0) return null;
        i += marker.length();
        int end = path.indexOf('/', i);
        return (end > i) ? path.substring(i, end) : path.substring(i);
    }

    /* ===== timestamped logging helpers ===== */
    private static String now() { return java.time.OffsetDateTime.now().toString(); }
    private static void logInfo(String subsystem, String target, String fmt, Object... args) {
        System.out.printf("%s [keycloak-scim-outbound][%s%s] %s%n",
                now(), subsystem, (target != null ? " " + target : ""), String.format(fmt, args));
    }
    private static void logErr(String subsystem, String target, String fmt, Object... args) {
        System.err.printf("%s [keycloak-scim-outbound][%s%s] %s%n",
                now(), subsystem, (target != null ? " " + target : ""), String.format(fmt, args));
    }

    @Override public void close() { }
}