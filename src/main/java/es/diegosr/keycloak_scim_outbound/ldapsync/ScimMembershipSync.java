package es.diegosr.keycloak_scim_outbound.ldapsync;

import es.diegosr.keycloak_scim_outbound.http.ScimClient;
import es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory;
import es.diegosr.keycloak_scim_outbound.util.ScimGroupMapper;
import es.diegosr.keycloak_scim_outbound.util.ScimMapper;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.UserStoragePrivateUtil;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Handles two distinct sync modes for SCIM outbound provisioning:
 *
 * 1. processPendingMembershipChanges() -- "changed users" sweep.
 *    Consumes the state written by LdapSyncNotifierMapper
 *    (MembershipState.PENDING_ATTRIBUTE_NAME) and pushes only users/groups that are
 *    flagged as changed since the last LDAP sync. Called by:
 *      - ScimTargetProviderFactory#syncSince (Keycloak "Synchronize changed users" button /
 *        Periodic Changed Users Sync scheduler)
 *
 * 2. fullSync() -- unconditional full reconciliation.
 *    Upserts every in-scope user and group regardless of pending flags.
 *    Optionally queries GET /Users and GET /Groups to deprovision stale SCIM entries
 *    (CFG_RECONCILE_USERS / CFG_RECONCILE_GROUPS). Called by:
 *      - ScimTargetProviderFactory#sync (Keycloak "Synchronize all users" button /
 *        Periodic Full Sync scheduler)
 *
 * PERFORMANCE NOTE: the pending sweep uses an indexed attribute lookup via
 * UserStoragePrivateUtil.userLocalStorage(session) -- never the aggregated session.users().
 * MembershipState.PENDING_ATTRIBUTE_NAME is a local bookkeeping attribute; searching it
 * through the aggregated view causes the LDAP provider to push it into a raw LDAP filter
 * which AD rejects with InvalidSearchFilterException.
 */
public final class ScimMembershipSync {

    private static final String LOG_TAG = "[keycloak-scim-outbound/LDAP-SYNC]";

    private ScimMembershipSync() { }

    // =========================================================================
    // Full sync
    // =========================================================================

    /**
     * Performs a full unconditional sync for the given SCIM target:
     *   1. Resolves the in-scope user set (all members of filterGroup, or all realm users).
     *   2. Upserts every in-scope user via SCIM /Users (POST or PATCH).
     *   3. If CFG_RECONCILE_USERS=true: queries GET /Users, deprovisions any SCIM user
     *      whose externalId is not in the in-scope set using the configured deprovisionAction.
     *   4. If CFG_PROVISION_GROUPS=true: upserts every in-scope group via SCIM /Groups.
     *   5. If CFG_RECONCILE_GROUPS=true: queries GET /Groups, deletes any SCIM group
     *      whose externalId is not in the in-scope Keycloak group set.
     *
     * @param componentIdFilter the componentId of the specific SCIM target to sync.
     * @return int[2]: [usersUpserted, failures]
     */
    public static int[] fullSync(KeycloakSession session, RealmModel realm, String componentIdFilter) {
        long start = System.currentTimeMillis();
        info("=== fullSync START realm=%s componentId=%s ===", realm.getName(), componentIdFilter);

        List<ComponentModel> targets = realm.getComponentsStream()
                .filter(c -> ScimTargetProviderFactory.ID.equals(c.getProviderId()))
                .filter(c -> componentIdFilter == null || componentIdFilter.equals(c.getId()))
                .toList();

        if (targets.isEmpty()) {
            debug("fullSync: no matching SCIM targets in realm=%s. Nothing to do.", realm.getName());
            return new int[]{0, 0};
        }

        int totalUpserted = 0;
        int totalFailures = 0;

        for (ComponentModel target : targets) {
            String base  = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_BASE_URL, null);
            String token = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_TOKEN, null);
            if (base == null || token == null) {
                err("fullSync: target=%s incomplete configuration (baseUrl/token). Skipping.", target.getName());
                totalFailures++;
                continue;
            }
            ScimClient client = new ScimClient(base, token);

            // -- Resolve in-scope users --
            List<UserModel> inScopeUsers = resolveInScopeUsers(session, realm, target);
            Set<String> inScopeExternalIds = new HashSet<>();
            info("fullSync: target=%s in-scope user count=%d", target.getName(), inScopeUsers.size());

            // -- Upsert each in-scope user --
            for (UserModel user : inScopeUsers) {
                inScopeExternalIds.add(user.getId());
                String scimUserName = computeScimUserName(target, user);
                if (scimUserName == null || scimUserName.isBlank()) {
                    err("fullSync: cannot resolve SCIM userName for user=%s target=%s. Skipping.",
                            user.getUsername(), target.getName());
                    totalFailures++;
                    continue;
                }
                try {
                    boolean ok = upsertUser(client, user, scimUserName);
                    if (ok) {
                        totalUpserted++;
                        debug("fullSync: UPSERT OK user=%s target=%s", user.getUsername(), target.getName());
                    } else {
                        totalFailures++;
                        err("fullSync: UPSERT FAILED user=%s target=%s", user.getUsername(), target.getName());
                    }
                } catch (Exception e) {
                    totalFailures++;
                    err("fullSync: EXCEPTION upserting user=%s target=%s: %s",
                            user.getUsername(), target.getName(), e.getMessage());
                }
            }

            // -- Reconcile stale SCIM users (optional) --
            boolean reconcileUsers = Boolean.parseBoolean(
                    ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_RECONCILE_USERS, "false"));
            if (reconcileUsers) {
                info("fullSync: reconciling /Users for target=%s (querying SCIM)", target.getName());
                Map<String, String> scimUsers = client.listAllUserExternalIds(); // scimId -> externalId
                for (Map.Entry<String, String> entry : scimUsers.entrySet()) {
                    String scimId     = entry.getKey();
                    String externalId = entry.getValue();
                    if (!inScopeExternalIds.contains(externalId)) {
                        info("fullSync: RECONCILE deprovision scimId=%s externalId=%s target=%s",
                                scimId, externalId, target.getName());
                        try {
                            boolean ok = deprovisionUserById(target, client, scimId);
                            if (!ok) {
                                totalFailures++;
                                err("fullSync: RECONCILE deprovision FAILED scimId=%s target=%s", scimId, target.getName());
                            }
                        } catch (Exception e) {
                            totalFailures++;
                            err("fullSync: RECONCILE deprovision EXCEPTION scimId=%s target=%s: %s",
                                    scimId, target.getName(), e.getMessage());
                        }
                    }
                }
            }

            // -- Group provisioning --
            if (!isGroupProvisioningEnabled(target)) continue;

            List<GroupModel> inScopeGroups = resolveInScopeGroups(session, realm, target);
            Set<String> inScopeGroupExternalIds = new HashSet<>();
            info("fullSync: target=%s in-scope group count=%d", target.getName(), inScopeGroups.size());

            for (GroupModel group : inScopeGroups) {
                inScopeGroupExternalIds.add(group.getId());
                try {
                    boolean ok = upsertScimGroup(client, group, target, session, realm);
                    if (ok) {
                        // Update local state to SYNCED so the pending sweep skips this group
                        group.setAttribute(GroupSyncState.STATE_ATTR_PREFIX + target.getId() + ".name",
                                List.of(group.getName()));
                        GroupSyncState.clearState(group, target.getId());
                        group.setAttribute(GroupSyncState.STATE_ATTR_PREFIX + target.getId(),
                                List.of(GroupSyncState.State.SYNCED.name()));
                        GroupSyncState.removePendingFlag(group, target.getId());
                        info("fullSync: GROUP UPSERT OK group='%s' target=%s", group.getName(), target.getName());
                    } else {
                        totalFailures++;
                        err("fullSync: GROUP UPSERT FAILED group='%s' target=%s", group.getName(), target.getName());
                    }
                } catch (Exception e) {
                    totalFailures++;
                    err("fullSync: GROUP UPSERT EXCEPTION group='%s' target=%s: %s",
                            group.getName(), target.getName(), e.getMessage());
                }
            }

            // -- Reconcile stale SCIM groups (optional) --
            boolean reconcileGroups = Boolean.parseBoolean(
                    ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_RECONCILE_GROUPS, "false"));
            if (reconcileGroups) {
                info("fullSync: reconciling /Groups for target=%s (querying SCIM)", target.getName());
                Map<String, String> scimGroups = client.listAllGroupExternalIds(); // scimId -> externalId
                for (Map.Entry<String, String> entry : scimGroups.entrySet()) {
                    String scimId     = entry.getKey();
                    String externalId = entry.getValue();
                    if (!inScopeGroupExternalIds.contains(externalId)) {
                        info("fullSync: RECONCILE delete scimGroupId=%s externalId=%s target=%s",
                                scimId, externalId, target.getName());
                        try {
                            boolean ok = client.deleteGroup(scimId);
                            if (!ok) {
                                totalFailures++;
                                err("fullSync: RECONCILE group delete FAILED scimId=%s target=%s", scimId, target.getName());
                            }
                        } catch (Exception e) {
                            totalFailures++;
                            err("fullSync: RECONCILE group delete EXCEPTION scimId=%s target=%s: %s",
                                    scimId, target.getName(), e.getMessage());
                        }
                    }
                }
            }
        }

        info("=== fullSync DONE realm=%s componentId=%s: upserted=%d failures=%d durationMs=%d ===",
                realm.getName(), componentIdFilter, totalUpserted, totalFailures,
                System.currentTimeMillis() - start);
        return new int[]{totalUpserted, totalFailures};
    }

    // =========================================================================
    // Changed-users (pending) sweep
    // =========================================================================

    /**
     * @param componentIdFilter if non-null, only process pending entries for this SCIM
     *                          target's componentId (used by the "Synchronize changed users"
     *                          trigger). If null, process all SCIM targets in the realm.
     */
    public static void processPendingMembershipChanges(KeycloakSession session, RealmModel realm, String componentIdFilter) {
        long start = System.currentTimeMillis();
        debug("=== processPendingMembershipChanges START realm=%s componentIdFilter=%s ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter);

        List<ComponentModel> targets = realm.getComponentsStream()
                .filter(c -> ScimTargetProviderFactory.ID.equals(c.getProviderId()))
                .filter(c -> componentIdFilter == null || componentIdFilter.equals(c.getId()))
                .toList();

        if (targets.isEmpty()) {
            debug("No matching SCIM outbound targets in realm=%s (filter=%s). Nothing to do.",
                    realm.getName(), componentIdFilter);
            return;
        }
        debug("Found %d SCIM target(s) to process in realm=%s: %s",
                targets.size(), realm.getName(), targets.stream().map(ComponentModel::getName).toList());

        int usersScanned = 0;
        int usersWithPending = 0;
        int pushedAdds = 0;
        int pushedRemoves = 0;
        int failures = 0;

        for (ComponentModel target : targets) {
            // Indexed lookup: only users flagged pending for THIS target, instead of
            // scanning every user in the realm. Always via local storage -- see class Javadoc.
            Map<String, UserModel> candidates = new LinkedHashMap<>();
            UserStoragePrivateUtil.userLocalStorage(session)
                    .searchForUserByUserAttributeStream(realm, MembershipState.PENDING_ATTRIBUTE_NAME,
                            MembershipState.pendingValue(target.getId()))
                    .forEach(u -> candidates.putIfAbsent(u.getId(), u));

            debug("Target=%s (id=%s): %d candidate user(s) flagged pending via indexed lookup.",
                    target.getName(), target.getId(), candidates.size());

            String base  = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_BASE_URL, null);
            String token = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_TOKEN, null);
            if (base == null || token == null) {
                err("Target=%s incomplete configuration (baseUrl/token). Skipping all pending entries for this target.",
                        target.getName());
                failures += candidates.size();
                continue;
            }
            ScimClient client = new ScimClient(base, token);

            for (UserModel user : candidates.values()) {
                usersScanned++;
                List<String> values = user.getAttributeStream(MembershipState.ATTRIBUTE_NAME).toList();
                if (values.isEmpty()) {
                    clearPendingFlag(session, realm, user, target.getId());
                    continue;
                }

                List<String> updatedValues = new ArrayList<>(values);
                boolean userChanged = false;
                boolean hadPendingForThisUser = false;

                for (String rawValue : values) {
                    Optional<MembershipState> parsed = MembershipState.parse(rawValue);
                    if (parsed.isEmpty()) {
                        debug("Skipping unparsable attribute value '%s' for user=%s", rawValue, user.getUsername());
                        continue;
                    }
                    MembershipState entry = parsed.get();

                    if (!entry.componentId().equals(target.getId())) continue;
                    if (entry.state() == MembershipState.State.SENT) continue;

                    hadPendingForThisUser = true;
                    debug("Pending entry found: user=%s target=%s group='%s' state=%s",
                            user.getUsername(), target.getName(), entry.groupName(), entry.state());

                    String scimUserName = computeScimUserName(target, user);
                    if (scimUserName == null || scimUserName.isBlank()) {
                        err("Could not resolve SCIM userName for user=%s target=%s. Skipping.",
                                user.getUsername(), target.getName());
                        failures++;
                        continue;
                    }

                    try {
                        if (entry.state() == MembershipState.State.NEW_ADDED) {
                            boolean ok = upsertUser(client, user, scimUserName);
                            if (ok) {
                                updatedValues.remove(rawValue);
                                MembershipState sent = new MembershipState(entry.componentId(), entry.groupName(), MembershipState.State.SENT);
                                updatedValues.add(sent.toValue());
                                userChanged = true;
                                pushedAdds++;
                                info("PUSHED ADD user=%s target=%s group='%s' -> SENT",
                                        user.getUsername(), target.getName(), entry.groupName());
                            } else {
                                failures++;
                                err("FAILED ADD push for user=%s target=%s group='%s'. Will retry next run.",
                                        user.getUsername(), target.getName(), entry.groupName());
                            }
                        } else if (entry.state() == MembershipState.State.NEW_DELETED) {
                            boolean ok = deprovisionUser(target, client, user.getId(), scimUserName);
                            if (ok) {
                                updatedValues.remove(rawValue);
                                userChanged = true;
                                pushedRemoves++;
                                info("PUSHED REMOVE user=%s target=%s group='%s' -> entry removed",
                                        user.getUsername(), target.getName(), entry.groupName());
                            } else {
                                failures++;
                                err("FAILED REMOVE push for user=%s target=%s group='%s'. Will retry next run.",
                                        user.getUsername(), target.getName(), entry.groupName());
                            }
                        }
                    } catch (Exception e) {
                        failures++;
                        err("EXCEPTION processing user=%s target=%s group='%s' state=%s: %s",
                                user.getUsername(), target.getName(), entry.groupName(), entry.state(), e.getMessage());
                    }
                }

                if (hadPendingForThisUser) usersWithPending++;

                if (userChanged) {
                    UserModel localUser = UserStoragePrivateUtil.userLocalStorage(session).getUserById(realm, user.getId());
                    if (localUser != null) {
                        localUser.setAttribute(MembershipState.ATTRIBUTE_NAME, updatedValues);
                        debug("Updated attribute for user=%s -> %s (via local storage)", user.getUsername(), updatedValues);
                    } else {
                        err("Could not resolve local storage user for id=%s (username=%s); attribute update skipped.",
                                user.getId(), user.getUsername());
                    }
                }

                boolean stillPendingForTarget = updatedValues.stream()
                        .map(MembershipState::parse)
                        .filter(Optional::isPresent)
                        .map(Optional::get)
                        .anyMatch(s -> s.componentId().equals(target.getId()) && s.state() != MembershipState.State.SENT);

                if (!stillPendingForTarget) {
                    clearPendingFlag(session, realm, user, target.getId());
                }
            }
        }

        long durationMs = System.currentTimeMillis() - start;
        info("=== processPendingMembershipChanges DONE realm=%s componentIdFilter=%s: "
                        + "usersScanned=%d usersWithPending=%d pushedAdds=%d pushedRemoves=%d failures=%d durationMs=%d ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter,
                usersScanned, usersWithPending, pushedAdds, pushedRemoves, failures, durationMs);

        // Process any pending SCIM group changes
        processPendingGroupChanges(session, realm, targets);
    }

    // =========================================================================
    // Group helpers (shared by both sync modes)
    // =========================================================================

    private static void processPendingGroupChanges(KeycloakSession session, RealmModel realm,
                                                   List<ComponentModel> targets) {
        for (ComponentModel target : targets) {
            if (!isGroupProvisioningEnabled(target)) continue;

            String base  = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_BASE_URL, null);
            String token = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_TOKEN, null);
            if (base == null || token == null) {
                err("Target=%s incomplete configuration (baseUrl/token). Skipping group sync.", target.getName());
                continue;
            }
            ScimClient client = new ScimClient(base, token);

            List<GroupModel> pendingGroups = GroupSyncState.findPendingGroups(realm);
            debug("Target=%s: %d group(s) with pending flags found.", target.getName(), pendingGroups.size());

            for (GroupModel group : pendingGroups) {
                Optional<GroupSyncState.State> stateOpt = GroupSyncState.getState(group, target.getId());
                if (stateOpt.isEmpty()) continue;

                GroupSyncState.State state = stateOpt.get();
                if (state == GroupSyncState.State.SYNCED) continue;

                debug("Processing group='%s' state=%s target=%s", group.getName(), state, target.getName());

                try {
                    if (state == GroupSyncState.State.NEEDS_SYNC) {
                        boolean ok = upsertScimGroup(client, group, target, session, realm);
                        if (ok) {
                            group.setAttribute(GroupSyncState.STATE_ATTR_PREFIX + target.getId() + ".name",
                                    List.of(group.getName()));
                            GroupSyncState.clearState(group, target.getId());
                            group.setAttribute(GroupSyncState.STATE_ATTR_PREFIX + target.getId(),
                                    List.of(GroupSyncState.State.SYNCED.name()));
                            GroupSyncState.removePendingFlag(group, target.getId());
                            info("GROUP SYNC OK group='%s' target=%s", group.getName(), target.getName());
                        } else {
                            err("GROUP SYNC FAILED group='%s' target=%s. Will retry next run.", group.getName(), target.getName());
                        }
                    } else if (state == GroupSyncState.State.NEEDS_DELETE) {
                        boolean ok = deleteScimGroup(client, group);
                        if (ok) {
                            GroupSyncState.clearState(group, target.getId());
                            group.removeAttribute(GroupSyncState.STATE_ATTR_PREFIX + target.getId() + ".name");
                            info("GROUP DELETE OK group='%s' target=%s", group.getName(), target.getName());
                        } else {
                            err("GROUP DELETE FAILED group='%s' target=%s. Will retry next run.", group.getName(), target.getName());
                        }
                    }
                } catch (Exception e) {
                    err("GROUP SYNC EXCEPTION group='%s' state=%s target=%s: %s",
                            group.getName(), state, target.getName(), e.getMessage());
                }
            }
        }
    }

    private static boolean upsertScimGroup(ScimClient client, GroupModel group,
                                           ComponentModel target, KeycloakSession session, RealmModel realm) {
        List<ScimGroupMapper.ScimMemberRef> members = resolveGroupMembers(client, group, target, session, realm);

        Optional<String> scimGroupId = client.findGroupIdByExternalId(group.getId());
        if (scimGroupId.isEmpty()) {
            scimGroupId = client.findGroupIdByDisplayName(group.getName());
        }

        if (scimGroupId.isEmpty()) {
            boolean created = client.createGroup(ScimGroupMapper.buildCreateGroup(group, members));
            if (created) return true;
            scimGroupId = client.findGroupIdByExternalId(group.getId());
            if (scimGroupId.isEmpty()) scimGroupId = client.findGroupIdByDisplayName(group.getName());
        }

        return scimGroupId
                .map(id -> client.patchGroup(id, ScimGroupMapper.buildReplaceGroupPatch(group.getName(), members)))
                .orElse(false);
    }

    private static boolean deleteScimGroup(ScimClient client, GroupModel group) {
        Optional<String> scimGroupId = client.findGroupIdByExternalId(group.getId());
        if (scimGroupId.isEmpty()) scimGroupId = client.findGroupIdByDisplayName(group.getName());
        if (scimGroupId.isEmpty()) {
            debug("Group '%s' not found in SCIM target; treating DELETE as NO-OP (already gone).", group.getName());
            return true;
        }
        return client.deleteGroup(scimGroupId.get());
    }

    private static List<ScimGroupMapper.ScimMemberRef> resolveGroupMembers(
            ScimClient client, GroupModel group, ComponentModel target,
            KeycloakSession session, RealmModel realm) {
        List<ScimGroupMapper.ScimMemberRef> refs = new ArrayList<>();
        session.users().getGroupMembersStream(realm, group).forEach(user -> {
            String scimUserName = computeScimUserName(target, user);
            if (scimUserName == null || scimUserName.isBlank()) return;
            Optional<String> scimId = resolveScimId(client, user.getId(), scimUserName);
            scimId.ifPresent(id -> refs.add(new ScimGroupMapper.ScimMemberRef(id, scimUserName)));
        });
        return refs;
    }

    // =========================================================================
    // In-scope resolution helpers
    // =========================================================================

    /**
     * Returns the set of Keycloak users that are in scope for the given SCIM target.
     * When CFG_FILTER_GROUP is set, only members of that group are returned.
     * Otherwise, all users in the realm are returned via searchForUserStream with an
     * empty filter map (compatible with Keycloak versions that do not have getUsersStream).
     */
    private static List<UserModel> resolveInScopeUsers(KeycloakSession session, RealmModel realm, ComponentModel target) {
        String filterGroup = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
        if (filterGroup != null && !filterGroup.isBlank()) {
            GroupModel group = findGroupByName(session, realm, filterGroup);
            if (group == null) {
                err("resolveInScopeUsers: filterGroup='%s' not found in realm=%s. Returning empty set.",
                        filterGroup, realm.getName());
                return List.of();
            }
            return session.users().getGroupMembersStream(realm, group).toList();
        }
        // searchForUserStream with an empty map returns all users and is available across
        // all supported Keycloak versions. getUsersStream(RealmModel) does not exist in
        // older KC versions and must not be used.
        return session.users().searchForUserStream(realm, Map.of()).toList();
    }

    /**
     * Returns the set of Keycloak groups that are in scope for group provisioning.
     * When CFG_GROUP_FILTER is set, only those named groups are returned.
     * When blank, falls back to CFG_FILTER_GROUP.
     * When neither is set, returns all top-level realm groups.
     */
    private static List<GroupModel> resolveInScopeGroups(KeycloakSession session, RealmModel realm, ComponentModel target) {
        String groupFilter = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_GROUP_FILTER, null);
        if (groupFilter == null || groupFilter.isBlank()) {
            groupFilter = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
        }
        if (groupFilter != null && !groupFilter.isBlank()) {
            List<GroupModel> result = new ArrayList<>();
            for (String name : groupFilter.split(",")) {
                String trimmed = name.trim();
                if (trimmed.isEmpty()) continue;
                GroupModel g = findGroupByName(session, realm, trimmed);
                if (g != null) {
                    result.add(g);
                } else {
                    err("resolveInScopeGroups: group='%s' not found in realm=%s. Skipping.", trimmed, realm.getName());
                }
            }
            return result;
        }
        return session.groups().getTopLevelGroupsStream(realm).toList();
    }

    private static GroupModel findGroupByName(KeycloakSession session, RealmModel realm, String name) {
        return session.groups().searchForGroupByNameStream(realm, name, false, 0, 1)
                .filter(g -> name.equals(g.getName()))
                .findFirst()
                .orElse(null);
    }

    // =========================================================================
    // SCIM push helpers
    // =========================================================================

    private static boolean isGroupProvisioningEnabled(ComponentModel target) {
        return Boolean.parseBoolean(
                ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_PROVISION_GROUPS, "false"));
    }

    private static void clearPendingFlag(KeycloakSession session, RealmModel realm, UserModel user, String componentId) {
        List<String> currentPending = user.getAttributeStream(MembershipState.PENDING_ATTRIBUTE_NAME).toList();
        String pendingValue = MembershipState.pendingValue(componentId);
        if (!currentPending.contains(pendingValue)) return;

        List<String> updatedPending = new ArrayList<>(currentPending);
        updatedPending.remove(pendingValue);

        UserModel localUser = UserStoragePrivateUtil.userLocalStorage(session).getUserById(realm, user.getId());
        if (localUser == null) {
            err("Could not resolve local storage user for id=%s (username=%s); pending-flag clear skipped for componentId=%s.",
                    user.getId(), user.getUsername(), componentId);
            return;
        }
        localUser.setAttribute(MembershipState.PENDING_ATTRIBUTE_NAME, updatedPending);
        debug("Cleared pending flag for user=%s componentId=%s -> %s", user.getUsername(), componentId, updatedPending);
    }

    private static String computeScimUserName(ComponentModel t, UserModel user) {
        String strategy = ScimTargetProviderFactory.get(t, ScimTargetProviderFactory.CFG_UNAME_STRATEGY, "username");
        switch (strategy) {
            case "email":
                return nullIfBlank(user.getEmail());
            case "attribute":
                String attr = ScimTargetProviderFactory.get(t, ScimTargetProviderFactory.CFG_UNAME_ATTR, null);
                return attr == null ? null : nullIfBlank(user.getFirstAttribute(attr));
            case "username":
            default:
                return user.getUsername();
        }
    }

    private static String nullIfBlank(String s) {
        return (s == null || s.isBlank()) ? null : s;
    }

    private static boolean upsertUser(ScimClient scim, UserModel user, String scimUserName) {
        final String externalId = user.getId();
        Optional<String> existingId = resolveScimId(scim, externalId, scimUserName);
        if (existingId.isEmpty()) {
            boolean created = scim.createUser(ScimMapper.buildCreateUser(user, scimUserName));
            if (created) return true;
            existingId = resolveScimId(scim, externalId, scimUserName);
            return existingId.map(id -> scim.patchUser(id, ScimMapper.buildPatchUser(user, externalId))).orElse(false);
        } else {
            return scim.patchUser(existingId.get(), ScimMapper.buildPatchUser(user, externalId));
        }
    }

    /**
     * Deprovisions a SCIM user whose Keycloak externalId is known (normal remove-from-scope path).
     * Looks up the SCIM id first by userName then by externalId.
     */
    private static boolean deprovisionUser(ComponentModel t, ScimClient scim, String externalId, String scimUserName) {
        Optional<String> id = resolveScimId(scim, externalId, scimUserName);
        if (id.isEmpty()) {
            debug("Deprovision NO-OP: user not found in SCIM target=%s (externalId=%s userName=%s)",
                    t.getName(), externalId, scimUserName);
            return true;
        }
        return deprovisionUserById(t, scim, id.get());
    }

    /**
     * Deprovisions a SCIM user by their SCIM id (used by the reconciliation pass, where the
     * SCIM id is already known from the GET /Users listing but the Keycloak user may be gone).
     * Applies the configured deprovisionAction (deactivate or delete).
     */
    private static boolean deprovisionUserById(ComponentModel t, ScimClient scim, String scimId) {
        String mode = ScimTargetProviderFactory.get(t, ScimTargetProviderFactory.CFG_DEPROVISION, "deactivate");
        if ("delete".equals(mode)) {
            return scim.deleteUser(scimId);
        }
        return scim.patchUser(scimId, ScimMapper.buildDeactivatePatch());
    }

    /**
     * Resolves the SCIM id for a user. Tries userName first (most SCIM servers honour this
     * filter reliably), then falls back to externalId lookup if userName yields nothing.
     */
    private static Optional<String> resolveScimId(ScimClient scim, String externalId, String scimUserName) {
        // Try userName first (most SCIM servers honour this filter reliably),
        // fall back to externalId lookup if userName yields nothing.
        Optional<String> id = (scimUserName != null && !scimUserName.isBlank())
                ? scim.findUserIdByUserName(scimUserName)
                : Optional.empty();
        if (id.isEmpty() && externalId != null && !externalId.isBlank()) {
            id = scim.findUserIdByExternalId(externalId);
        }
        return id;
    }

    /* ===== logging ===== */

    private static String now() {
        return java.time.OffsetDateTime.now().toString();
    }

    private static void debug(String fmt, Object... args) {
        System.out.printf("%s %s DEBUG %s%n", now(), LOG_TAG, String.format(fmt, args));
    }

    private static void info(String fmt, Object... args) {
        System.out.printf("%s %s INFO  %s%n", now(), LOG_TAG, String.format(fmt, args));
    }

    private static void err(String fmt, Object... args) {
        System.err.printf("%s %s ERROR %s%n", now(), LOG_TAG, String.format(fmt, args));
    }
}
