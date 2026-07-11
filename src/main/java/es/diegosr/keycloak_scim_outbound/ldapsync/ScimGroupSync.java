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
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
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

    /**
     * Mode values for CFG_LDAP_GROUP_PROV_MODE.
     * Must stay in sync with the list options in ScimTargetProviderFactory.PROPS.
     */
    public static final String MODE_DELTA_ONLY        = "Delta provision only";
    public static final String MODE_DELTA_DEPROVISION = "Delta provision and deprovision";
    public static final String MODE_FULL              = "Full";

    private ScimGroupSync() {}

    // =========================================================================
    // Delta flush
    // =========================================================================

    /**
     * Process only groups that have a pending entry for the given target.
     * The provisioning mode governs which pending states are flushed and whether the
     * cross-check runs afterward:
     *
     *   "Delta provision only"            -- flush NEW_ADDED only; no cross-check
     *   "Delta provision and deprovision" -- flush NEW_ADDED + NEW_DELETED; then run
     *                                        crossCheckGroupMembers over all in-scope groups
     *
     * "Full" mode is never routed here; callers must use processFullGroupSync instead.
     *
     * @param componentIdFilter if non-null, scope to that target only (manual sync).
     *                          If null, process all targets (kept for symmetry, not used currently).
     * @param mode              value of CFG_LDAP_GROUP_PROV_MODE as read by runSweep.
     */
    public static void processPendingGroupMembershipChanges(KeycloakSession session, RealmModel realm,
                                                            String componentIdFilter, String mode) {
        long start = System.currentTimeMillis();
        debug("=== processPendingGroupMembershipChanges START realm=%s componentIdFilter=%s mode=%s ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter, mode);

        List<ComponentModel> targets = scimTargets(realm, componentIdFilter);
        if (targets.isEmpty()) {
            debug("No matching SCIM targets in realm=%s (filter=%s). Nothing to do.",
                    realm.getName(), componentIdFilter);
            return;
        }

        boolean flushDeletes = MODE_DELTA_DEPROVISION.equals(mode);
        boolean runCrossCheck = MODE_DELTA_DEPROVISION.equals(mode);

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

            // Determine all in-scope groups for this target. Used both for the pending flush and
            // (when mode is "Delta provision and deprovision") for the cross-check.
            // Keycloak does not expose a searchForGroupByAttributeStream in all versions, so we
            // iterate the full group stream and filter by attribute. This is acceptable because the
            // number of groups is typically small (tens to low hundreds), unlike users (potentially thousands).
            List<GroupModel> inScopeGroups = resolveInScopeGroups(session, realm, target);
            debug("Target=%s: %d in-scope group(s) total.", target.getName(), inScopeGroups.size());

            // Candidate groups: in-scope groups that have a pending flag for this target.
            List<GroupModel> candidates = inScopeGroups.stream()
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

                    // Skip NEW_DELETED entries when mode is "Delta provision only"
                    if (entry.state() == GroupMembershipState.State.NEW_DELETED && !flushDeletes) {
                        debug("Mode=%s: skipping NEW_DELETED for group=%s userId=%s target=%s",
                                mode, group.getName(), entry.userId(), target.getName());
                        continue;
                    }

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
                            debug("Calling client.patchGroup(add) group=%s scimGroupId=%s userId=%s scimUserId=%s target=%s",
                                    group.getName(), scimGroupId.get(), entry.userId(), scimUserId.get(), target.getName());
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
                            debug("Calling client.patchGroup(remove) group=%s scimGroupId=%s userId=%s scimUserId=%s target=%s",
                                    group.getName(), scimGroupId.get(), entry.userId(), scimUserId.get(), target.getName());
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

            // Cross-check: runs once per target after all pending entries are flushed.
            // Iterates ALL in-scope groups, not just those that had pending entries.
            // Cost: one HTTP GET per in-scope group per delta sync cycle in this mode.
            // Acceptable for deployments with tens of groups.
            if (runCrossCheck) {
                crossCheckGroupMembers(session, realm, target, client, inScopeGroups);
            }
        }

        long durationMs = System.currentTimeMillis() - start;
        info("=== processPendingGroupMembershipChanges DONE realm=%s componentIdFilter=%s mode=%s: "
                        + "groupsProcessed=%d pushedAdds=%d pushedRemoves=%d failures=%d durationMs=%d ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter, mode,
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
                    if (filterGroupName != null && !filterGroupName.isBlank()
                            && !scopedUserIds.contains(member.getId())) {
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
                    debug("Calling client.patchGroup(replace) group=%s scimGroupId=%s target=%s members=%d",
                            group.getName(), scimGroupId.get(), target.getName(), scimMemberIds.size());
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
    // Cross-check
    // =========================================================================

    /**
     * Verifies that the remote SCIM group member list matches the local Keycloak state
     * for each in-scope group. Removes any remote members absent from the local KC group
     * (intersected with the CFG_FILTER_GROUP scope boundary).
     *
     * Only called in "Delta provision and deprovision" mode, after the pending-entry flush
     * has completed. No adds are performed here: Keycloak is the authority and missing
     * members are handled by the pending-entry flush or the next LDAP sync cycle.
     *
     * Cost: one HTTP GET per in-scope group per delta sync cycle. For deployments with
     * tens of groups this is acceptable. If this becomes a concern, consider adding a
     * configurable cross-check interval.
     *
     * Cross-check removals are fire-and-forget: they do not write GroupMembershipState
     * attributes. Failed removals will be retried on the next sync cycle.
     */
    private static void crossCheckGroupMembers(KeycloakSession session, RealmModel realm,
                                               ComponentModel target, ScimClient client,
                                               List<GroupModel> inScopeGroups) {
        debug("crossCheckGroupMembers START target=%s groups=%d", target.getName(), inScopeGroups.size());

        // Determine user provisioning scope boundary: members of CFG_FILTER_GROUP
        String filterGroupName = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
        Set<String> scopedUserIds = new HashSet<>();
        if (filterGroupName != null && !filterGroupName.isBlank()) {
            session.groups().searchForGroupByNameStream(realm, filterGroupName, true, null, null)
                    .findFirst()
                    .ifPresent(fg -> session.users().getGroupMembersStream(realm, fg)
                            .forEach(u -> scopedUserIds.add(u.getId())));
        }

        int removedTotal = 0;
        int failuresTotal = 0;

        for (GroupModel group : inScopeGroups) {
            // Step 1: resolve the SCIM group; skip if not found (do not auto-create)
            Optional<String> scimGroupIdOpt = resolveScimGroupId(client, group.getId(), group.getName());
            if (scimGroupIdOpt.isEmpty()) {
                debug("crossCheck: SCIM group not found for KC group '%s' (id=%s). Skipping.",
                        group.getName(), group.getId());
                continue;
            }
            String scimGroupId = scimGroupIdOpt.get();

            // Step 2: fetch the current remote member list via the flat API.
            // A missing or empty members array is treated as an empty list -- never an error.
            List<String> remoteScimUserIds = client.getGroupMembers(scimGroupId);
            debug("crossCheck: group=%s scimGroupId=%s remote members=%d",
                    group.getName(), scimGroupId, remoteScimUserIds.size());
            if (remoteScimUserIds.isEmpty()) {
                continue;
            }

            // Step 3: build the local KC member set (scoped), resolved to SCIM user IDs
            Set<String> localScimUserIds = new HashSet<>();
            List<UserModel> groupMembers = session.users().getGroupMembersStream(realm, group).toList();
            for (UserModel member : groupMembers) {
                // Apply scope boundary: only consider users in CFG_FILTER_GROUP
                if (filterGroupName != null && !filterGroupName.isBlank()
                        && !scopedUserIds.contains(member.getId())) {
                    continue;
                }
                String scimUserName = computeScimUserName(target, member);
                Optional<String> scimUserId = resolveScimUserId(client, member.getId(), scimUserName);
                scimUserId.ifPresent(localScimUserIds::add);
            }

            // Step 4: remove remote members absent from the local set.
            // No adds are performed here -- only removals.
            for (String remoteId : remoteScimUserIds) {
                if (localScimUserIds.contains(remoteId)) {
                    continue;
                }
                debug("crossCheck: removing excess remote member scimUserId=%s from group=%s target=%s",
                        remoteId, group.getName(), target.getName());
                try {
                    boolean ok = client.patchGroup(scimGroupId,
                            ScimMapper.buildGroupMemberPatch("remove", remoteId));
                    if (ok) {
                        removedTotal++;
                        info("CROSS-CHECK REMOVE group=%s scimUserId=%s target=%s -> OK",
                                group.getName(), remoteId, target.getName());
                    } else {
                        failuresTotal++;
                        err("CROSS-CHECK REMOVE group=%s scimUserId=%s target=%s -> FAILED. Will retry next cycle.",
                                group.getName(), remoteId, target.getName());
                    }
                } catch (Exception e) {
                    failuresTotal++;
                    err("CROSS-CHECK REMOVE EXCEPTION group=%s scimUserId=%s target=%s: %s",
                            group.getName(), remoteId, target.getName(), e.getMessage());
                }
            }
        }

        debug("crossCheckGroupMembers DONE target=%s removedTotal=%d failuresTotal=%d",
                target.getName(), removedTotal, failuresTotal);
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

    /**
     * Resolve the SCIM group id for a Keycloak group.
     *
     * Strategy:
     * 1. Query by externalId. If exactly one result is returned, use it.
     * 2. If zero results: group not found by externalId, fall through to displayName.
     * 3. If more than one result: the SCIM server returned an ambiguous match for a
     *    UUID-based filter (server-side data issue). Do not pick an arbitrary match --
     *    fall back to displayName lookup and log a warning.
     */
    private static Optional<String> resolveScimGroupId(ScimClient client, String externalId, String displayName) {
        debug("resolveScimGroupId CALL externalId=%s displayName=%s", externalId, displayName);

        Optional<String> id = Optional.empty();
        if (externalId != null && !externalId.isBlank()) {
            ScimClient.ScimLookupResult r = client.findGroupByExternalId(externalId);
            if (r.totalResults() == 1) {
                id = r.id();
            } else if (r.totalResults() > 1) {
                // Ambiguous: the SCIM server returned multiple groups for a UUID-based
                // externalId filter. This indicates a server-side data issue.
                // Do not pick an arbitrary match -- fall back to displayName lookup.
                debug("resolveScimGroupId: externalId=%s returned %d results (ambiguous), falling back to displayName",
                        externalId, r.totalResults());
            }
            // totalResults == 0: not found, fall through to displayName
        }

        if (id.isEmpty() && displayName != null && !displayName.isBlank()) {
            debug("resolveScimGroupId: externalId lookup empty, falling back to displayName=%s", displayName);
            id = client.findGroupIdByDisplayName(displayName);
        }
        debug("resolveScimGroupId RESULT externalId=%s displayName=%s -> %s", externalId, displayName, id.orElse("<none>"));
        return id;
    }

    private static Optional<String> resolveScimUserId(ScimClient client, String externalId, String scimUserName) {
        debug("resolveScimUserId CALL externalId=%s scimUserName=%s", externalId, scimUserName);
        Optional<String> id = (externalId != null && !externalId.isBlank())
                ? client.findUserIdByExternalId(externalId)
                : Optional.empty();
        if (id.isEmpty() && scimUserName != null && !scimUserName.isBlank()) {
            debug("resolveScimUserId: externalId lookup empty, falling back to userName=%s", scimUserName);
            id = client.findUserIdByUserName(scimUserName);
        }
        debug("resolveScimUserId RESULT externalId=%s scimUserName=%s -> %s", externalId, scimUserName, id.orElse("<none>"));
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
