package es.diegosr.keycloak_scim_outbound;

import es.diegosr.keycloak_scim_outbound.http.ScimClient;
import es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory;
import es.diegosr.keycloak_scim_outbound.util.ScimMapper;

import static es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory.*;

import org.jboss.logging.Logger;
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
import java.util.Optional;
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

    private static final Logger LOG = Logger.getLogger(ScimEventListenerProvider.class);

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
        final String userId   = (user != null) ? user.getId()       : event.getUserId();
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

            // e.g. "users/{uid}/groups/{gid}" or "groups/{gid}/members/{uid}"
            final String raw  = adminEvent.getResourcePath();
            final String path = raw.startsWith("/") ? raw : "/" + raw;

            // Common path patterns:
            //  - /users/{userId}/groups/{groupId}
            //  - /groups/{groupId}/members/{userId}
            String userId  = extractSegmentAfter(path, "/users/");
            String groupId = extractSegmentAfter(path, "/groups/");

            // fallback for "groups/{gid}/members/{uid}"
            if (userId  == null) userId  = extractSegmentAfter(path, "/members/");
            if (groupId == null) groupId = extractSegmentAfter(path, "/groups/");

            if (userId == null || groupId == null) {
                LOG.infof("SCIM membership -- Cannot parse membership path: %s", raw);
                return;
            }

            final UserModel  user      = session.users().getUserById(realm, userId);
            final GroupModel group     = session.groups().getGroupById(realm, groupId);
            final String     groupName = (group != null ? group.getName() : null);
            final String     username  = (user  != null ? user.getUsername() : "(unknown)");

            if (groupName == null) {
                LOG.infof("SCIM membership -- Group not found for id=%s (path=%s)", groupId, path);
                return;
            }

            final List<ComponentModel> targets = realm.getComponentsStream()
                    .filter(c -> ScimTargetProviderFactory.ID.equals(c.getProviderId()))
                    .toList();

            for (ComponentModel t : targets) {
                final String base  = ScimTargetProviderFactory.get(t, ScimTargetProviderFactory.CFG_BASE_URL, null);
                final String token = ScimTargetProviderFactory.get(t, ScimTargetProviderFactory.CFG_TOKEN, null);
                if (base == null || token == null) {
                    LOG.errorf("SCIM [%s] -- Incomplete configuration (baseUrl/token). Skipping membership event.",
                            t.getName());
                    continue;
                }

                final ScimClient    client      = new ScimClient(base, token);
                final OperationType op          = adminEvent.getOperationType();
                final String        debounceKey = "GM:" + realm.getId() + ":" + userId + ":" + groupId + ":" + op;
                final long          now         = Instant.now().toEpochMilli();
                final Long          last        = debounce.put(debounceKey, now);
                if (last != null && (now - last) < DEBOUNCE_MS) continue;

                final String scimUserName = computeScimUserName(t, user, username);

                // A) Filter-group user provisioning (existing behavior)
                final String cfgGroup = ScimTargetProviderFactory.get(t, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
                if (cfgGroup != null && !cfgGroup.isBlank() && cfgGroup.equals(groupName)) {
                    if (scimUserName == null || scimUserName.isBlank()) {
                        LOG.errorf("SCIM [%s] -- Cannot resolve SCIM userName for user=%s. Skipping filter-group event.",
                                t.getName(), username);
                    } else {
                        try {
                            switch (op) {
                                case CREATE -> { // user ADDED to group
                                    boolean changed = upsertUser(client, user, scimUserName);
                                    LOG.infof("SCIM [%s] -- GROUP ADD user=%s group=%s -> %s",
                                            t.getName(), scimUserName, groupName, changed ? "OK" : "NO-OP");
                                }
                                case DELETE -> { // user REMOVED from group
                                    boolean changed = deprovisionUser(t, client, userId, scimUserName);
                                    LOG.infof("SCIM [%s] -- GROUP REMOVE user=%s group=%s -> %s",
                                            t.getName(), scimUserName, groupName, changed ? "OK" : "NO-OP");
                                }
                                default -> {}
                            }
                        } catch (Exception e) {
                            LOG.errorf("SCIM [%s] -- GROUP %s user=%s group=%s ERROR: %s",
                                    t.getName(), op, scimUserName, groupName, e.getMessage());
                        }
                    }
                }

                // B) Sync group membership in SCIM (only when syncGroups is explicitly enabled)
                if ("true".equalsIgnoreCase(get(t, CFG_SYNC_GROUPS, "false"))
                        && isGroupAllowedForSync(t, groupName)) {
                    try {
                        final Optional<String> scimGroupId = resolveScimGroupId(client, groupId, groupName);
                        if (scimGroupId.isEmpty()) {
                            LOG.infof("SCIM [%s] -- MEMBERSHIP %s: SCIM group not found (groupId=%s name=%s), skipping",
                                    t.getName(), op, groupId, groupName);
                        } else {
                            final Optional<String> scimUserId = resolveScimId(client, userId, scimUserName);
                            if (scimUserId.isEmpty()) {
                                LOG.infof("SCIM [%s] -- MEMBERSHIP %s: SCIM user not found (userId=%s), skipping",
                                        t.getName(), op, userId);
                            } else {
                                boolean ok = switch (op) {
                                    case CREATE -> client.patchGroup(scimGroupId.get(),
                                            ScimMapper.buildGroupMemberPatch("add", scimUserId.get()));
                                    case DELETE -> client.patchGroup(scimGroupId.get(),
                                            ScimMapper.buildGroupMemberPatch("remove", scimUserId.get()));
                                    default -> false;
                                };
                                LOG.infof("SCIM [%s] -- MEMBERSHIP %s user=%s group=%s -> %s",
                                        t.getName(), op, username, groupName, ok ? "OK" : "NO-OP");
                            }
                        }
                    } catch (Exception e) {
                        LOG.errorf("SCIM [%s] -- MEMBERSHIP %s group=%s ERROR: %s",
                                t.getName(), op, groupName, e.getMessage());
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

            final UserModel user     = session.users().getUserById(realm, userId);
            final String    username = (user != null) ? user.getUsername() : "(unknown)";

            final OperationType op = adminEvent.getOperationType();
            switch (op) {
                case CREATE -> dispatch("CREATE", realm, userId, username, user, null);
                case UPDATE -> dispatch("UPDATE", realm, userId, username, user, null);
                case DELETE -> dispatch("DELETE", realm, userId, username, user, null);
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
                    LOG.errorf("SCIM [%s] -- Incomplete configuration (baseUrl/token). Skipping GROUP event.",
                            t.getName());
                    continue;
                }
                if (!"true".equalsIgnoreCase(get(t, CFG_SYNC_GROUPS, "false"))) continue;
                if (!isGroupAllowedForSync(t, groupName)) continue;

                final ScimClient client = new ScimClient(base, token);
                try {
                    switch (op) {
                        case CREATE -> {
                            if (groupName == null) {
                                LOG.errorf("SCIM [%s] -- GROUP CREATE: group not found (id=%s)",
                                        t.getName(), groupId);
                                break;
                            }
                            boolean ok = client.createGroup(ScimMapper.buildCreateGroup(groupName, groupId));
                            LOG.infof("SCIM [%s] -- GROUP CREATE name=%s -> %s",
                                    t.getName(), groupName, ok ? "OK" : "CONFLICT/NO-OP");
                        }
                        case UPDATE -> {
                            if (groupName == null) {
                                LOG.errorf("SCIM [%s] -- GROUP UPDATE: group not found (id=%s)",
                                        t.getName(), groupId);
                                break;
                            }
                            final Optional<String> scimId = resolveScimGroupId(client, groupId, groupName);
                            if (scimId.isPresent()) {
                                boolean ok = client.patchGroup(scimId.get(),
                                        ScimMapper.buildPatchGroupDisplayName(groupName));
                                LOG.infof("SCIM [%s] -- GROUP UPDATE name=%s -> %s",
                                        t.getName(), groupName, ok ? "OK" : "FAILED");
                            } else {
                                boolean ok = client.createGroup(ScimMapper.buildCreateGroup(groupName, groupId));
                                LOG.infof("SCIM [%s] -- GROUP UPDATE (upsert) name=%s -> %s",
                                        t.getName(), groupName, ok ? "OK" : "FAILED");
                            }
                        }
                        case DELETE -> {
                            final Optional<String> scimId = client.findGroupIdByExternalId(groupId);
                            if (scimId.isPresent()) {
                                boolean ok = client.deleteGroup(scimId.get());
                                LOG.infof("SCIM [%s] -- GROUP DELETE groupId=%s -> %s",
                                        t.getName(), groupId, ok ? "OK" : "FAILED");
                            } else {
                                LOG.infof("SCIM [%s] -- GROUP DELETE groupId=%s -> NOT FOUND in SCIM",
                                        t.getName(), groupId);
                            }
                        }
                        default -> {}
                    }
                } catch (Exception e) {
                    LOG.errorf("SCIM [%s] -- GROUP %s groupId=%s ERROR: %s",
                            t.getName(), op, groupId, e.getMessage());
                }
            }
        }
        // other resource types -> ignore
    }

    /* ===== Core dispatch ===== */

    private void dispatch(String action, RealmModel realm, String userId, String username,
                          UserModel user, Map<String, String> details) {
        // Debounce to reduce double delivery (user event + admin event)
        String key  = realm.getId() + ":" + action + ":" + userId;
        long   now  = Instant.now().toEpochMilli();
        Long   last = debounce.put(key, now);
        if (last != null && (now - last) < DEBOUNCE_MS) return;

        List<ComponentModel> targets = realm.getComponentsStream()
                .filter(c -> ScimTargetProviderFactory.ID.equals(c.getProviderId()))
                .toList();

        for (ComponentModel t : targets) {
            handleTarget(t, action, realm, userId, username, user);
        }
    }

    private void handleTarget(ComponentModel t, String action, RealmModel realm,
                               String userId, String username, UserModel user) {
        final String base  = get(t, CFG_BASE_URL, null);
        final String token = get(t, CFG_TOKEN, null);
        final String group = get(t, CFG_FILTER_GROUP, null);

        if (base == null || token == null) {
            LOG.errorf("SCIM [%s] -- Incomplete configuration (baseUrl/token). Skipping.", t.getName());
            return;
        }

        final String scimUserName = computeScimUserName(t, user, username);
        if (scimUserName == null || scimUserName.isBlank()) {
            LOG.errorf("SCIM [%s] -- Could not resolve SCIM 'userName' for user=%s. Skipping.",
                    t.getName(), username);
            return;
        }

        if (!"DELETE".equals(action) && group != null && !group.isBlank()) {
            if (user == null) {
                LOG.infof("SCIM [%s] -- User model not found; skipping due to group filter.", t.getName());
                return;
            }
            boolean inGroup = user.getGroupsStream().anyMatch(g -> g.getName().equals(group));
            if (!inGroup) {
                LOG.infof("SCIM [%s] -- User %s does not belong to group '%s'. Skipping.",
                        t.getName(), username, group);
                return;
            }
        }

        ScimClient client = new ScimClient(base, token);

        try {
            boolean changed = switch (action) {
                case "CREATE", "UPDATE" -> upsertUser(client, user, scimUserName);
                case "DELETE"           -> deprovisionUser(t, client, userId, scimUserName);
                default                 -> false;
            };

            if (changed) {
                LOG.infof("SCIM [%s] -- %s targetUserName=%s realm=%s OK",
                        t.getName(), action, scimUserName, realm.getName());
            } else {
                LOG.infof("SCIM [%s] -- %s targetUserName=%s realm=%s NO-OP (not found / not changed)",
                        t.getName(), action, scimUserName, realm.getName());
            }
        } catch (Exception e) {
            LOG.errorf("SCIM [%s] -- %s targetUserName=%s ERROR: %s",
                    t.getName(), action, scimUserName, e.getMessage());
        }
    }

    // Resolve SCIM userName from strategy
    private String computeScimUserName(ComponentModel t, UserModel user, String fallbackUsername) {
        String strategy = get(t, CFG_UNAME_STRATEGY, "username");
        LOG.debugf("SCIM [%s] -- Using userNameStrategy=%s", t.getName(), strategy);

        if (user == null) return fallbackUsername; // best-effort on deletes

        return switch (strategy) {
            case "email"     -> nullIfBlank(user.getEmail());
            case "attribute" -> {
                String attr = get(t, CFG_UNAME_ATTR, null);
                yield attr == null ? null : nullIfBlank(user.getFirstAttribute(attr));
            }
            default          -> user.getUsername(); // "username" and any unknown value
        };
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
            LOG.infof("SCIM [%s] -- Deprovision NO-OP: user not found (externalId=%s userName=%s)",
                    t.getName(), externalId, scimUserName);
            return false;
        }

        String  mode          = get(t, CFG_DEPROVISION, "deactivate");
        String  effectiveMode = mode;
        boolean ok;
        if ("delete".equals(mode)) {
            ok = scim.deleteUser(id.get());
        } else if ("deactivate".equals(mode)) {
            ok = scim.patchUser(id.get(), ScimMapper.buildDeactivatePatch());
        } else {
            LOG.errorf("SCIM [%s] -- Invalid deprovisionAction=%s; falling back to deactivate",
                    t.getName(), mode);
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
     *
     * When CFG_SYNC_GROUPS_FILTER is blank: only the group named by CFG_FILTER_GROUP is in scope.
     * When CFG_SYNC_GROUPS_FILTER is set: the group name must match the Java regex.
     * groupName=null: returns true only when filter is set (so that DELETE events where the
     * group is already gone can still be attempted by regex-configured targets), and false
     * for the blank-filter case (no name to match against CFG_FILTER_GROUP).
     */
    private boolean isGroupAllowedForSync(ComponentModel t, String groupName) {
        String filter = get(t, CFG_SYNC_GROUPS_FILTER, null);
        if (filter == null || filter.isBlank()) {
            // No regex: only the CFG_FILTER_GROUP is in scope
            if (groupName == null) return false;
            String filterGroup = get(t, CFG_FILTER_GROUP, null);
            return groupName.equals(filterGroup);
        }
        // Regex filter: null groupName passes so DELETE events are not silently dropped
        if (groupName == null) return true;
        try {
            return groupName.matches(filter);
        } catch (java.util.regex.PatternSyntaxException e) {
            LOG.errorf("SCIM [%s] -- Invalid CFG_SYNC_GROUPS_FILTER regex '%s': %s",
                    t.getName(), filter, e.getMessage());
            return false;
        }
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

    @Override public void close() { }
}
