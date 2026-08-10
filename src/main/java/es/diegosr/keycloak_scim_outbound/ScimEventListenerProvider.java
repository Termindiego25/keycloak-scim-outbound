package es.diegosr.keycloak_scim_outbound;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.diegosr.keycloak_scim_outbound.http.ScimClient;
import es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory;
import es.diegosr.keycloak_scim_outbound.util.ScimMapper;

import static es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory.*;

import org.keycloak.component.ComponentModel;
import org.keycloak.events.Details;
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
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiFunction;
import java.util.function.LongSupplier;

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
    private static final ObjectMapper JSON = new ObjectMapper();

    private final KeycloakSession session;
    private final BiFunction<String, String, ScimClient> scimClientFactory;
    private final LongSupplier clock;

    private static final Set<EventType> USER_EVENTS_OF_INTEREST = EnumSet.of(
            EventType.REGISTER,
            EventType.UPDATE_PROFILE,
            EventType.UPDATE_EMAIL,
            EventType.UPDATE_CREDENTIAL,
            EventType.DELETE_ACCOUNT
    );

    /** Debounce state to avoid duplicated pushes when KC emits the same event twice. */
    private final ConcurrentHashMap<UserDebounceKey, Long> userDebounce = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<MembershipDebounceKey, MembershipDebounceEntry> membershipDebounce =
            new ConcurrentHashMap<>();
    private static final long DEBOUNCE_MS = 2000;

    private record UserDebounceKey(String realmId, String userId, String action) { }

    private record MembershipDebounceKey(String realmId, String userId, String groupId, String targetId) { }

    private record MembershipDebounceEntry(OperationType operation, long timestamp) { }

    public ScimEventListenerProvider(KeycloakSession session) {
        this(session, ScimClient::new, () -> Instant.now().toEpochMilli());
    }

    ScimEventListenerProvider(KeycloakSession session,
                              BiFunction<String, String, ScimClient> scimClientFactory,
                              LongSupplier clock) {
        this.session = session;
        this.scimClientFactory = scimClientFactory;
        this.clock = clock;
    }

    /* ===== User events ===== */
    @Override
    public void onEvent(Event event) {
        if (!USER_EVENTS_OF_INTEREST.contains(event.getType())) return;

        RealmModel realm = session.realms().getRealm(event.getRealmId());
        if (realm == null) return;

        UserModel user = session.users().getUserById(realm, event.getUserId());
        final String userId = (user != null) ? user.getId() : event.getUserId();
        final String username = (user != null)
                ? user.getUsername()
                : usernameFromDetails(event.getDetails());

        switch (event.getType()) {
            case REGISTER -> dispatch("CREATE", realm, userId, username, user);
            case UPDATE_PROFILE, UPDATE_EMAIL -> dispatch("UPDATE", realm, userId, username, user);
            case UPDATE_CREDENTIAL -> {
                Map<String, String> d = event.getDetails();
                if (d != null && "password".equalsIgnoreCase(d.get("credential_type"))) {
                    dispatch("UPDATE", realm, userId, username, user);
                }
            }
            case DELETE_ACCOUNT -> dispatch("DELETE", realm, userId, username, user);
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

            final String raw = adminEvent.getResourcePath(); // e.g. "users/{uid}/groups/{gid}" or "groups/{gid}/members/{uid}"
            final String path = raw.startsWith("/") ? raw : "/" + raw;  // normalize to leading slash

            // Common path patterns:
            //  - /users/{userId}/groups/{groupId}
            //  - /groups/{groupId}/members/{userId}
            String userId  = extractSegmentAfter(path, "/users/");
            String groupId = extractSegmentAfter(path, "/groups/");

            // fallback for "groups/{gid}/members/{uid}"
            if (userId == null)  userId  = extractSegmentAfter(path, "/members/");
            if (groupId == null) groupId = extractSegmentAfter(path, "/groups/");

            if (userId == null || groupId == null) {
                logInfo("SCIM", "membership", "Cannot parse membership path: %s", raw);
                return;
            }

            final UserModel  user  = session.users().getUserById(realm, userId);
            final GroupModel group = session.groups().getGroupById(realm, groupId);
            final String groupName = (group != null ? group.getName() : null);
            final String username  = (user != null ? user.getUsername() : null);

            if (groupName == null) {
                logInfo("SCIM", "membership", "Group not found for id=%s (path=%s)", groupId, path);
                return;
            }

            // For each SCIM target configured in this realm
            final List<ComponentModel> targets = realm.getComponentsStream()
                    .filter(c -> ScimTargetProviderFactory.ID.equals(c.getProviderId()))
                    .toList();

            for (ComponentModel t : targets) {
                final String base  = ScimTargetProviderFactory.get(t, ScimTargetProviderFactory.CFG_BASE_URL, null);
                final String token = ScimTargetProviderFactory.get(t, ScimTargetProviderFactory.CFG_TOKEN, null);
                if (base == null || token == null) {
                    logErr("SCIM", t.getName(), "Incomplete configuration (baseUrl/token). Skipping membership event.");
                    continue;
                }

                final ScimClient client = scimClientFactory.apply(base, token);
                final OperationType op  = adminEvent.getOperationType();
                final long now = clock.getAsLong();
                if (shouldDebounceMembershipEvent(
                        realm.getId(), userId, groupId, op, t.getId(), now)) {
                    continue;
                }

                final String scimUserName = computeScimUserName(t, user, username);

                // A) Filter-group user provisioning (existing behavior)
                final String cfgGroup = ScimTargetProviderFactory.get(t, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
                if (cfgGroup != null && !cfgGroup.isBlank() && cfgGroup.equals(groupName)) {
                    if (op != OperationType.DELETE && (scimUserName == null || scimUserName.isBlank())) {
                        logErr("SCIM", t.getName(), "Cannot resolve SCIM userName for user=%s. Skipping filter-group event.", username);
                    } else {
                        try {
                            switch (op) {
                                case CREATE -> { // user ADDED to group
                                    boolean changed = upsertUser(client, user, scimUserName);
                                    logInfo("SCIM", t.getName(), "GROUP ADD user=%s group=%s -> %s",
                                            scimUserName, groupName, changed ? "OK" : "NO-OP");
                                }
                                case DELETE -> { // user REMOVED from group
                                    boolean changed = deprovisionUser(t, client, userId, scimUserName);
                                    logInfo("SCIM", t.getName(), "GROUP REMOVE user=%s group=%s -> %s",
                                            scimUserName, groupName, changed ? "OK" : "NO-OP");
                                }
                                default -> {}
                            }
                        } catch (Exception e) {
                            logErr("SCIM", t.getName(), "GROUP %s user=%s group=%s ERROR: %s",
                                    op, scimUserName, groupName, e.getMessage());
                        }
                    }
                }

                // B) Sync group membership in SCIM (only when syncGroups is explicitly enabled)
                if ("true".equalsIgnoreCase(get(t, CFG_SYNC_GROUPS, "false"))
                        && isGroupAllowedForSync(t, groupName)) {
                    try {
                        final Optional<String> scimGroupId = resolveScimGroupId(client, groupId, groupName);
                        if (scimGroupId.isEmpty()) {
                            logInfo("SCIM", t.getName(), "MEMBERSHIP %s: SCIM group not found (groupId=%s name=%s), skipping",
                                    op, groupId, groupName);
                        } else {
                            final Optional<String> scimUserId = resolveScimId(client, userId, scimUserName);
                            if (scimUserId.isEmpty()) {
                                logInfo("SCIM", t.getName(), "MEMBERSHIP %s: SCIM user not found (userId=%s), skipping",
                                        op, userId);
                            } else {
                                boolean ok = switch (op) {
                                    case CREATE -> client.patchGroup(scimGroupId.get(), ScimMapper.buildGroupMemberPatch("add", scimUserId.get()));
                                    case DELETE -> client.patchGroup(scimGroupId.get(), ScimMapper.buildGroupMemberPatch("remove", scimUserId.get()));
                                    default -> false;
                                };
                                logInfo("SCIM", t.getName(), "MEMBERSHIP %s user=%s group=%s -> %s",
                                        op, username, groupName, ok ? "OK" : "NO-OP");
                            }
                        }
                    } catch (Exception e) {
                        logErr("SCIM", t.getName(), "MEMBERSHIP %s group=%s ERROR: %s", op, groupName, e.getMessage());
                    }
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

            final OperationType op = adminEvent.getOperationType();
            final UserModel user = session.users().getUserById(realm, userId);
            final String username = (user != null)
                    ? user.getUsername()
                    : (op == OperationType.DELETE ? usernameFromAdminRepresentation(adminEvent) : null);

            switch (op) {
                case CREATE -> dispatch("CREATE", realm, userId, username, user);
                case UPDATE -> dispatch("UPDATE", realm, userId, username, user);
                case DELETE -> dispatch("DELETE", realm, userId, username, user);
                default -> { /* ignore */ }
            }
        }

        // 3) GROUP CRUD EVENTS
        if (adminEvent.getResourceType() == ResourceType.GROUP) {
            final RealmModel realm = session.realms().getRealm(adminEvent.getRealmId());
            if (realm == null) return;

            final String raw     = adminEvent.getResourcePath();
            final String path    = (raw != null && !raw.startsWith("/")) ? "/" + raw : raw;
            final String groupId = extractSegmentAfter(path, "/groups/");
            if (groupId == null) return;

            final GroupModel    group     = session.groups().getGroupById(realm, groupId);
            final String        groupName = (group != null) ? group.getName() : null;
            final OperationType op        = adminEvent.getOperationType();

            final List<ComponentModel> targets = realm.getComponentsStream()
                    .filter(c -> ScimTargetProviderFactory.ID.equals(c.getProviderId()))
                    .toList();

            for (ComponentModel t : targets) {
                final String base  = get(t, CFG_BASE_URL, null);
                final String token = get(t, CFG_TOKEN, null);
                if (base == null || token == null) {
                    logErr("SCIM", t.getName(), "Incomplete configuration (baseUrl/token). Skipping GROUP event.");
                    continue;
                }
                if (!"true".equalsIgnoreCase(get(t, CFG_SYNC_GROUPS, "false"))) continue;
                if (!isGroupAllowedForSync(t, groupName)) continue;
                final ScimClient client = scimClientFactory.apply(base, token);
                try {
                    switch (op) {
                        case CREATE -> {
                            if (groupName == null) {
                                logErr("SCIM", t.getName(), "GROUP CREATE: group not found (id=%s)", groupId);
                                break;
                            }
                            boolean ok = client.createGroup(ScimMapper.buildCreateGroup(groupName, groupId));
                            logInfo("SCIM", t.getName(), "GROUP CREATE name=%s -> %s", groupName, ok ? "OK" : "CONFLICT/NO-OP");
                        }
                        case UPDATE -> {
                            if (groupName == null) {
                                logErr("SCIM", t.getName(), "GROUP UPDATE: group not found (id=%s)", groupId);
                                break;
                            }
                            final Optional<String> scimId = resolveScimGroupId(client, groupId, groupName);
                            if (scimId.isPresent()) {
                                boolean ok = client.patchGroup(scimId.get(), ScimMapper.buildPatchGroupDisplayName(groupName));
                                logInfo("SCIM", t.getName(), "GROUP UPDATE name=%s -> %s", groupName, ok ? "OK" : "FAILED");
                            } else {
                                boolean ok = client.createGroup(ScimMapper.buildCreateGroup(groupName, groupId));
                                logInfo("SCIM", t.getName(), "GROUP UPDATE (upsert) name=%s -> %s", groupName, ok ? "OK" : "FAILED");
                            }
                        }
                        case DELETE -> {
                            final Optional<String> scimId = client.findGroupIdByExternalId(groupId);
                            if (scimId.isPresent()) {
                                boolean ok = client.deleteGroup(scimId.get());
                                logInfo("SCIM", t.getName(), "GROUP DELETE groupId=%s -> %s", groupId, ok ? "OK" : "FAILED");
                            } else {
                                logInfo("SCIM", t.getName(), "GROUP DELETE groupId=%s -> NOT FOUND in SCIM", groupId);
                            }
                        }
                        default -> {}
                    }
                } catch (Exception e) {
                    logErr("SCIM", t.getName(), "GROUP %s groupId=%s ERROR: %s", op, groupId, e.getMessage());
                }
            }
        }
        // other resource types -> ignore
    }

    boolean shouldDebounceMembershipEvent(String realmId, String userId, String groupId,
                                           OperationType operation, String targetId, long now) {
        MembershipDebounceKey key = new MembershipDebounceKey(realmId, userId, groupId, targetId);
        MembershipDebounceEntry current = new MembershipDebounceEntry(operation, now);
        MembershipDebounceEntry previous = membershipDebounce.put(key, current);
        return previous != null
                && previous.operation() == operation
                && isWithinDebounceWindow(previous.timestamp(), now);
    }

    boolean shouldDebounceUserEvent(String realmId, String userId, String action, long now) {
        UserDebounceKey key = new UserDebounceKey(realmId, userId, action);
        Long previous = userDebounce.put(key, now);
        return previous != null && isWithinDebounceWindow(previous, now);
    }

    private static boolean isWithinDebounceWindow(long previous, long now) {
        long elapsed = now - previous;
        return elapsed >= 0 && elapsed < DEBOUNCE_MS;
    }

    /* ===== Core dispatch ===== */

    private void dispatch(String action, RealmModel realm, String userId, String username, UserModel user) {
        // Debounce to reduce double delivery (user event + admin event)
        long now = clock.getAsLong();
        if (shouldDebounceUserEvent(realm.getId(), userId, action, now)) return;

        List<ComponentModel> targets = realm.getComponentsStream()
                .filter(c -> ScimTargetProviderFactory.ID.equals(c.getProviderId()))
                .toList();

        for (ComponentModel t : targets) {
            handleTarget(t, action, realm, userId, username, user);
        }
    }

    private static String usernameFromDetails(Map<String, String> details) {
        return details == null ? null : nullIfBlank(details.get(Details.USERNAME));
    }

    private static String usernameFromAdminRepresentation(AdminEvent adminEvent) {
        String representation = adminEvent.getRepresentation();
        if (representation == null || representation.isBlank()) return null;

        try {
            JsonNode username = JSON.readTree(representation).path("username");
            return username.isTextual() ? nullIfBlank(username.asText()) : null;
        } catch (Exception e) {
            logErr("SCIM", "delete", "Could not parse deleted user representation; continuing with externalId only.");
            return null;
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
        if (!"DELETE".equals(action) && (scimUserName == null || scimUserName.isBlank())) {
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

        ScimClient client = scimClientFactory.apply(base, token);

        try {
            boolean changed = switch (action) {
                case "CREATE", "UPDATE" -> upsertUser(client, user, scimUserName);
                case "DELETE" -> deprovisionUser(t, client, userId, scimUserName);
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

        if (user == null) {
            return "username".equals(strategy) ? nullIfBlank(fallbackUsername) : null;
        }

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
     * Prefers externalId for lookup (userName can change with the configured strategy),
     * falling back to userName for users provisioned before externalId existed.
     * The PATCH also sets externalId when missing, so legacy users get it on update.
     */
    private boolean upsertUser(ScimClient scim, UserModel user, String scimUserName) {
        if (user == null) return false;

        final String externalId = user.getId();
        var existingId = resolveScimId(scim, externalId, scimUserName);
        if (existingId.isEmpty()) {
            boolean created = scim.createUser(ScimMapper.buildCreateUser(user, scimUserName));
            if (created) return true;

            // Creation failed (likely 409). Re-resolve and PATCH.
            existingId = resolveScimId(scim, externalId, scimUserName);
            return existingId.map(id -> scim.patchUser(id, ScimMapper.buildPatchUser(user, externalId))).orElse(false);
        } else {
            return scim.patchUser(existingId.get(), ScimMapper.buildPatchUser(user, externalId));
        }
    }

    /**
     * Deprovision a user according to the target's configured behavior:
     *  - "delete"     -> hard DELETE /Users/{id}
     *  - "deactivate" -> PATCH active=false (default, documented behavior)
     * Resolves the SCIM id by externalId first, then by userName as a fallback.
     */
    private boolean deprovisionUser(ComponentModel t, ScimClient scim, String externalId, String scimUserName) {
        var id = resolveScimId(scim, externalId, scimUserName);
        if (id.isEmpty()) {
            logInfo("SCIM", t.getName(), "Deprovision NO-OP: user not found (externalId=%s userName=%s)",
                    externalId, scimUserName);
            return false;
        }

        String mode = get(t, CFG_DEPROVISION, "deactivate");
        String effectiveMode = mode;
        boolean ok;
        if ("delete".equals(mode)) {
            ok = scim.deleteUser(id.get());
        } else if ("deactivate".equals(mode)) {
            ok = scim.patchUser(id.get(), ScimMapper.buildDeactivatePatch());
        } else {
            logErr("SCIM", t.getName(), "Invalid deprovisionAction=%s; falling back to deactivate", mode);
            effectiveMode = "deactivate";
            ok = scim.patchUser(id.get(), ScimMapper.buildDeactivatePatch());
        }
        if (!ok) {
            throw new IllegalStateException(String.format(
                    "deprovision %s failed for scimId=%s externalId=%s userName=%s",
                    effectiveMode, id.get(), externalId, scimUserName));
        }
        return ok;
    }

    /**
     * Returns true if the group should be synced for this target.
     * When CFG_SYNC_GROUPS_FILTER is empty, all groups pass.
     * When it contains entries, only matching groups (case-insensitive) pass.
     * groupName=null always passes so that DELETE events (where the group is already gone) are attempted.
     */
    private boolean isGroupAllowedForSync(ComponentModel t, String groupName) {
        String filter = get(t, CFG_SYNC_GROUPS_FILTER, null);
        if (filter == null || filter.isBlank()) return true;
        if (groupName == null) return true;
        for (String name : filter.split(",")) {
            if (name.trim().equalsIgnoreCase(groupName)) return true;
        }
        return false;
    }

    /** Prefer externalId lookup; fall back to displayName for groups. */
    private Optional<String> resolveScimGroupId(ScimClient scim, String externalId, String displayName) {
        Optional<String> id = (externalId != null && !externalId.isBlank())
                ? scim.findGroupIdByExternalId(externalId)
                : Optional.empty();
        if (id.isEmpty() && displayName != null && !displayName.isBlank()) {
            id = scim.findGroupIdByDisplayName(displayName);
        }
        return id;
    }

    /** Prefer externalId lookup; fall back to userName for legacy users without externalId. */
    private Optional<String> resolveScimId(ScimClient scim, String externalId, String scimUserName) {
        Optional<String> id = (externalId != null && !externalId.isBlank())
                ? scim.findUserIdByExternalId(externalId)
                : Optional.empty();
        if (id.isEmpty() && scimUserName != null && !scimUserName.isBlank()) {
            id = scim.findUserIdByUserName(scimUserName);
        }
        return id;
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
