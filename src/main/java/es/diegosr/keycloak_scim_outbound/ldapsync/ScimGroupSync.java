package es.diegosr.keycloak_scim_outbound.ldapsync;

import es.diegosr.keycloak_scim_outbound.http.ScimClient;
import es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory;
import es.diegosr.keycloak_scim_outbound.util.ScimMapper;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Flushes pending SCIM /Groups LDAP-driven membership changes to the configured SCIM targets.
 * Parallel to ScimMembershipSync (which handles /Users).
 *
 * Two entry points:
 *   processPendingGroupMembershipChanges -- delta flush; only groups marked pending
 *   processFullGroupSync                 -- full PATCH replace for all in-scope groups
 *
 * Called from ScimTargetProviderFactory.runSweep() after user sync has completed.
 * User sync always runs first so every in-scope user already has a SCIM ID by the time
 * group sync resolves member IDs.
 *
 * Group attributes (GroupMembershipState.*) are written directly on GroupModel --
 * groups are realm-local, not federated storage, so no UserStoragePrivateUtil is needed.
 */
public final class ScimGroupSync {

    private static final String LOG_TAG = "[keycloak-scim-outbound/LDAP-GROUP-SYNC]";

    private ScimGroupSync() {}

    // =========================================================================
    // Delta flush
    // =========================================================================

    /**
     * Process only groups that have a pending entry for the given target.
     *
     * @param componentIdFilter if non-null, scope to that target only (manual sync).
     *                          If null, process all targets (kept for symmetry, not used currently).
     */
    public static void processPendingGroupMembershipChanges(KeycloakSession session, RealmModel realm,
                                                            String componentIdFilter) {
        long start = System.currentTimeMillis();
        debug("=== processPendingGroupMembershipChanges START realm=%s componentIdFilter=%s ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter);

        List<ComponentModel> targets = scimTargets(realm, componentIdFilter);
        if (targets.isEmpty()) {
            debug("No matching SCIM targets in realm=%s (filter=%s). Nothing to do.",
                    realm.getName(), componentIdFilter);
            return;
        }

        int groupsProcessed = 0;
        int pushedAdds = 0;
        int pushedRemoves = 0;
        int failures = 0;

        for (ComponentModel target : targets) {
            if (!"true".equalsIgnoreCase(ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_SYNC_GROUPS, "false"))) {
                continue;
            }

            String base  = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_BASE_URL, null);
            String token = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_TOKEN, null);
            if (base == null || token == null) {
                err("Target=%s incomplete config (baseUrl/token). Skipping group sync.", target.getName());
                continue;
            }
            ScimClient client = new ScimClient(base, token);

            // Candidate groups: all realm groups that have a pending flag for this target.
            // Keycloak does not expose a searchForGroupByAttributeStream in all versions,
            // so we iterate the full group stream and filter by attribute. This is acceptable
            // because the number of groups is typically small (tens to low hundreds), unlike
            // users (potentially thousands).
            List<GroupModel> candidates = session.groups().getGroupsStream(realm)
                    .filter(g -> {
                        List<String> pending = g.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME).toList();
                        return pending.contains(GroupMembershipState.pendingValue(target.getId()));
                    })
                    .collect(Collectors.toList());

            debug("Target=%s: %d candidate group(s) with pending entries.", target.getName(), candidates.size());

            for (GroupModel group : candidates) {
                groupsProcessed++;
                List<String> stateValues = new ArrayList<>(
                        group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME).toList());

                Optional<String> scimGroupId = resolveScimGroupId(client, group.getId(), group.getName());
                if (scimGroupId.isEmpty()) {
                    err("Target=%s: SCIM group not found for KC group '%s' (id=%s). Skipping.",
                            target.getName(), group.getName(), group.getId());
                    continue;
                }

                boolean groupChanged = false;
                List<String> updatedValues = new ArrayList<>(stateValues);

                for (String raw : stateValues) {
                    Optional<GroupMembershipState> parsed = GroupMembershipState.parse(raw);
                    if (parsed.isEmpty()) continue;
                    GroupMembershipState entry = parsed.get();
                    if (!entry.componentId().equals(target.getId())) continue;
                    if (entry.state() == GroupMembershipState.State.SENT) continue;

                    // Resolve KC user to get their SCIM userName for fallback lookup
                    UserModel kcUser = session.users().getUserById(realm, entry.userId());
                    String scimUserName = kcUser != null ? computeScimUserName(target, kcUser) : null;

                    Optional<String> scimUserId = resolveScimUserId(client, entry.userId(), scimUserName);
                    if (scimUserId.isEmpty()) {
                        err("Target=%s: SCIM user not found for userId=%s (group=%s). Skipping this member entry.",
                                target.getName(), entry.userId(), group.getName());
                        failures++;
                        continue;
                    }

                    try {
                        if (entry.state() == GroupMembershipState.State.NEW_ADDED) {
                            boolean ok = client.patchGroup(scimGroupId.get(),
                                    ScimMapper.buildGroupMemberPatch("add", scimUserId.get()));
                            if (ok) {
                                updatedValues.remove(raw);
                                GroupMembershipState sent = new GroupMembershipState(
                                        entry.componentId(), entry.userId(), GroupMembershipState.State.SENT);
                                updatedValues.add(sent.toValue());
                                groupChanged = true;
                                pushedAdds++;
                                info("PUSHED ADD group=%s userId=%s target=%s -> SENT",
                                        group.getName(), entry.userId(), target.getName());
                            } else {
                                failures++;
                                err("FAILED ADD push group=%s userId=%s target=%s. Will retry.",
                                        group.getName(), entry.userId(), target.getName());
                            }
                        } else if (entry.state() == GroupMembershipState.State.NEW_DELETED) {
                            boolean ok = client.patchGroup(scimGroupId.get(),
                                    ScimMapper.buildGroupMemberPatch("remove", scimUserId.get()));
                            if (ok) {
                                updatedValues.remove(raw);
                                groupChanged = true;
                                pushedRemoves++;
                                info("PUSHED REMOVE group=%s userId=%s target=%s -> entry removed",
                                        group.getName(), entry.userId(), target.getName());
                            } else {
                                failures++;
                                err("FAILED REMOVE push group=%s userId=%s target=%s. Will retry.",
                                        group.getName(), entry.userId(), target.getName());
                            }
                        }
                    } catch (Exception e) {
                        failures++;
                        err("EXCEPTION group=%s userId=%s target=%s state=%s: %s",
                                group.getName(), entry.userId(), target.getName(), entry.state(), e.getMessage());
                    }
                }

                if (groupChanged) {
                    writeGroupState(group, target.getId(), updatedValues);
                }
            }
        }

        long durationMs = System.currentTimeMillis() - start;
        info("=== processPendingGroupMembershipChanges DONE realm=%s componentIdFilter=%s: "
                        + "groupsProcessed=%d pushedAdds=%d pushedRemoves=%d failures=%d durationMs=%d ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter,
                groupsProcessed, pushedAdds, pushedRemoves, failures, durationMs);
    }

    // =========================================================================
    // Full sync
    // =========================================================================

    /**
     * Full sync: send a complete PATCH replace for all in-scope groups.
     * Called by sync() (Synchronize all) and by syncSince() when CFG_LDAP_GROUP_PROV_MODE=Full.
     * After sending, clears ALL GroupMembershipState + pending attributes for the target.
     *
     * @param componentIdFilter if non-null, scope to that target only.
     */
    public static void processFullGroupSync(KeycloakSession session, RealmModel realm,
                                            String componentIdFilter) {
        long start = System.currentTimeMillis();
        debug("=== processFullGroupSync START realm=%s componentIdFilter=%s ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter);

        List<ComponentModel> targets = scimTargets(realm, componentIdFilter);
        if (targets.isEmpty()) {
            debug("No matching SCIM targets in realm=%s (filter=%s). Nothing to do.",
                    realm.getName(), componentIdFilter);
            return;
        }

        int groupsProcessed = 0;
        int failures = 0;

        for (ComponentModel target : targets) {
            if (!"true".equalsIgnoreCase(ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_SYNC_GROUPS, "false"))) {
                continue;
            }

            String base  = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_BASE_URL, null);
            String token = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_TOKEN, null);
            if (base == null || token == null) {
                err("Target=%s incomplete config (baseUrl/token). Skipping full group sync.", target.getName());
                continue;
            }
            ScimClient client = new ScimClient(base, token);

            // Determine in-scope groups for this target
            List<GroupModel> inScopeGroups = resolveInScopeGroups(session, realm, target);
            debug("Target=%s: %d in-scope group(s) for full sync.", target.getName(), inScopeGroups.size());

            // Determine user provisioning scope: members of CFG_FILTER_GROUP
            String filterGroupName = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
            List<String> scopedUserIds = new ArrayList<>();
            if (filterGroupName != null && !filterGroupName.isBlank()) {
                session.groups().searchForGroupByNameStream(realm, filterGroupName, true, null, null)
                        .findFirst()
                        .ifPresent(fg -> session.users().getGroupMembersStream(realm, fg)
                                .forEach(u -> scopedUserIds.add(u.getId())));
            }

            for (GroupModel group : inScopeGroups) {
                groupsProcessed++;

                Optional<String> scimGroupId = resolveScimGroupId(client, group.getId(), group.getName());
                if (scimGroupId.isEmpty()) {
                    err("Target=%s: SCIM group not found for KC group '%s' (id=%s). Skipping.",
                            target.getName(), group.getName(), group.getId());
                    failures++;
                    continue;
                }

                // Build the full member list: current KC members, intersected with scoped users
                List<String> scimMemberIds = new ArrayList<>();
                List<UserModel> groupMembers = session.users().getGroupMembersStream(realm, group).toList();
                for (UserModel member : groupMembers) {
                    if (!filterGroupName.isBlank() && !scopedUserIds.contains(member.getId())) {
                        // user is not in scope for user provisioning -- skip
                        continue;
                    }
                    String scimUserName = computeScimUserName(target, member);
                    Optional<String> scimUserId = resolveScimUserId(client, member.getId(), scimUserName);
                    if (scimUserId.isEmpty()) {
                        debug("Target=%s: SCIM user not found for userId=%s (group=%s). Skipping member.",
                                target.getName(), member.getId(), group.getName());
                        continue;
                    }
                    scimMemberIds.add(scimUserId.get());
                }

                try {
                    boolean ok = client.patchGroup(scimGroupId.get(),
                            ScimMapper.buildGroupMemberReplace(scimMemberIds));
                    if (ok) {
                        info("FULL SYNC group=%s target=%s members=%d -> OK",
                                group.getName(), target.getName(), scimMemberIds.size());
                        // Clear all state for this target on this group
                        clearGroupState(group, target.getId());
                    } else {
                        failures++;
                        err("FULL SYNC group=%s target=%s FAILED.", group.getName(), target.getName());
                    }
                } catch (Exception e) {
                    failures++;
                    err("FULL SYNC EXCEPTION group=%s target=%s: %s",
                            group.getName(), target.getName(), e.getMessage());
                }
            }
        }

        long durationMs = System.currentTimeMillis() - start;
        info("=== processFullGroupSync DONE realm=%s componentIdFilter=%s: "
                        + "groupsProcessed=%d failures=%d durationMs=%d ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter,
                groupsProcessed, failures, durationMs);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Returns true if the given group name is in scope for SCIM /Groups sync on this target.
     * When CFG_SYNC_GROUPS_FILTER is blank: only the group named by CFG_FILTER_GROUP is in scope.
     * When CFG_SYNC_GROUPS_FILTER is set: the group name must match the regex.
     * groupName=null always returns false.
     */
    static boolean isGroupInScope(ComponentModel t, String groupName) {
        if (groupName == null) return false;
        String filter = ScimTargetProviderFactory.get(t, ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER, null);
        if (filter == null || filter.isBlank()) {
            String filterGroup = ScimTargetProviderFactory.get(t, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
            return groupName.equals(filterGroup);
        }
        return groupName.matches(filter);
    }

    private static List<GroupModel> resolveInScopeGroups(KeycloakSession session, RealmModel realm,
                                                          ComponentModel target) {
        String filter = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER, null);
        if (filter == null || filter.isBlank()) {
            // No regex -- only the CFG_FILTER_GROUP itself is in scope
            String filterGroupName = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
            if (filterGroupName == null || filterGroupName.isBlank()) return List.of();
            return session.groups().searchForGroupByNameStream(realm, filterGroupName, true, null, null)
                    .collect(Collectors.toList());
        }
        // Regex filter: iterate all groups and match
        return session.groups().getGroupsStream(realm)
                .filter(g -> g.getName() != null && g.getName().matches(filter))
                .collect(Collectors.toList());
    }

    private static List<ComponentModel> scimTargets(RealmModel realm, String componentIdFilter) {
        return realm.getComponentsStream()
                .filter(c -> ScimTargetProviderFactory.ID.equals(c.getProviderId()))
                .filter(c -> componentIdFilter == null || componentIdFilter.equals(c.getId()))
                .toList();
    }

    private static Optional<String> resolveScimGroupId(ScimClient client, String externalId, String displayName) {
        Optional<String> id = (externalId != null && !externalId.isBlank())
                ? client.findGroupIdByExternalId(externalId)
                : Optional.empty();
        if (id.isEmpty() && displayName != null && !displayName.isBlank()) {
            id = client.findGroupIdByDisplayName(displayName);
        }
        return id;
    }

    private static Optional<String> resolveScimUserId(ScimClient client, String externalId, String scimUserName) {
        Optional<String> id = (externalId != null && !externalId.isBlank())
                ? client.findUserIdByExternalId(externalId)
                : Optional.empty();
        if (id.isEmpty() && scimUserName != null && !scimUserName.isBlank()) {
            id = client.findUserIdByUserName(scimUserName);
        }
        return id;
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

    /**
     * Recomputes and writes GroupMembershipState and pending attributes for the given target
     * on the given group, based on the updated state values list.
     */
    private static void writeGroupState(GroupModel group, String componentId, List<String> updatedValues) {
        // Recompute pending flag: present if any entry for this target has state != SENT
        boolean hasPending = updatedValues.stream()
                .map(GroupMembershipState::parse)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .anyMatch(e -> e.componentId().equals(componentId)
                        && e.state() != GroupMembershipState.State.SENT);

        List<String> allPending = new ArrayList<>(
                group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME).toList());
        String pendingFlag = GroupMembershipState.pendingValue(componentId);
        if (hasPending && !allPending.contains(pendingFlag)) {
            allPending.add(pendingFlag);
        } else if (!hasPending) {
            allPending.remove(pendingFlag);
        }

        group.setAttribute(GroupMembershipState.ATTRIBUTE_NAME, updatedValues);
        group.setAttribute(GroupMembershipState.PENDING_ATTRIBUTE_NAME, allPending);
        debug("Updated group state for group=%s componentId=%s -> membershipState=%s pending=%s",
                group.getName(), componentId, updatedValues, allPending);
    }

    /**
     * Removes all GroupMembershipState and pending attribute entries for the given target
     * from this group. Called after a successful full PATCH replace.
     */
    private static void clearGroupState(GroupModel group, String componentId) {
        List<String> currentState = group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME).toList();
        List<String> updatedState = GroupMembershipState.removeAllForComponent(currentState, componentId);

        List<String> allPending = new ArrayList<>(
                group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME).toList());
        allPending.remove(GroupMembershipState.pendingValue(componentId));

        group.setAttribute(GroupMembershipState.ATTRIBUTE_NAME, updatedState);
        group.setAttribute(GroupMembershipState.PENDING_ATTRIBUTE_NAME, allPending);
        debug("Cleared group state for group=%s componentId=%s", group.getName(), componentId);
    }

    /* ===== logging ===== */

    private static String now() {
        return java.time.OffsetDateTime.now().toString();
    }

    private static void debug(String fmt, Object... args) {
        System.out.printf("%s %s DEBUG %s%n", now(), LOG_TAG, String.format(fmt, args));
    }

    private static void info(String fmt, Object... args) {
        System.out.printf("%s %s INFO %s%n", now(), LOG_TAG, String.format(fmt, args));
    }

    private static void err(String fmt, Object... args) {
        System.err.printf("%s %s ERROR %s%n", now(), LOG_TAG, String.format(fmt, args));
    }
}
