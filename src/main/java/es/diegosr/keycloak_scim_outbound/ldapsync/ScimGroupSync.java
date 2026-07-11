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
    public static final String MODE_DELTA_ONLY        = "Delta (add members)";
    public static final String MODE_DELTA_DEPROVISION = "Delta (add and remove members)";
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
     *   "Delta (add members)"            -- flush NEW_ADDED only; no cross-check
     *   "Delta (add and remove members)" -- flush NEW_ADDED + NEW_DELETED; then run
     *                                       crossCheckGroupMembers over all in-scope groups
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
            String removeForm = ScimTargetProviderFactory.get(target,
                    ScimTargetProviderFactory.CFG_GROUP_MEMBER_REMOVE_FORM,
                    ScimMapper.REMOVE_FORM_RFC_PATH_FILTER);

            // Determine all in-scope groups for this target. Used both for the pending flush and
            // (when mode is "Delta (add and remove members)") for the cross-check.
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

                // Upsert: resolve the SCIM group, creating it if it does not exist yet.
                // Groups that originate purely from LDAP are never created by the event-driven
                // path (Keycloak fires no GROUP_CREATE admin event during LDAP sync).
                Optional<String> scimGroupId = upsertScimGroup(client, target, group);
                if (scimGroupId.isEmpty()) {
                    continue; // upsertScimGroup already logged the error
                }

                boolean groupChanged = false;
                List<String> updatedValues = new ArrayList<>(stateValues);

                for (String raw : stateValues) {
                    Optional<GroupMembershipState> parsed = GroupMembershipState.parse(raw);
                    if (parsed.isEmpty()) continue;
                    GroupMembershipState entry = parsed.get();
                    if (!entry.componentId().equals(target.getId())) continue;
                    if (entry.state() == GroupMembershipState.State.SENT) continue;

                    // Skip NEW_DELETED entries when mode is "Delta (add members)"
                    if (entry.state() == GroupMembershipState.State.NEW_DELETED && !flushDeletes) {
                        debug("Mode=%s: skipping NEW_DELETED for group=%s userId=%s target=%s",
                                mode, group.getName(), entry.userId(), target.getName());
                        continue;
                    }

                    UserModel kcUser = session.users().getUserById(realm, entry.userId());
                    String scimUserName = kcUser != null ? computeScimUserName(target, kcUser) : null;

                    Optional<String> scimUserId = resolveScimUserId(client, target, entry.userId(), scimUserName);
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
                                    ScimMapper.buildGroupMemberPatch("remove", scimUserId.get(), removeForm));
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

            List<GroupModel> inScopeGroups = resolveInScopeGroups(session, realm, target);
            debug("Target=%s: %d in-scope group(s) for full sync.", target.getName(), inScopeGroups.size());

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

                // Upsert: resolve the SCIM group, creating it if it does not exist yet.
                // Groups that originate purely from LDAP are never created by the event-driven
                // path (Keycloak fires no GROUP_CREATE admin event during LDAP sync).
                Optional<String> scimGroupId = upsertScimGroup(client, target, group);
                if (scimGroupId.isEmpty()) {
                    failures++;
                    continue; // upsertScimGroup already logged the error
                }

                List<String> scimMemberIds = new ArrayList<>();
                List<UserModel> groupMembers = session.users().getGroupMembersStream(realm, group).toList();
                for (UserModel member : groupMembers) {
                    if (filterGroupName != null && !filterGroupName.isBlank()
                            && !scopedUserIds.contains(member.getId())) {
                        continue;
                    }
                    String scimUserName = computeScimUserName(target, member);
                    Optional<String> scimUserId = resolveScimUserId(client, target, member.getId(), scimUserName);
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
     * Only called in "Delta (add and remove members)" mode, after the pending-entry flush
     * has completed. No adds are performed here: Keycloak is the authority and missing
     * members are handled by the pending-entry flush or the next LDAP sync cycle.
     *
     * Cross-check removals are fire-and-forget: they do not write GroupMembershipState
     * attributes. Failed removals will be retried on the next sync cycle.
     *
     * This method must NOT auto-create missing SCIM groups. If a group is not found
     * remotely during the cross-check, it is simply skipped. Group creation is handled
     * by upsertScimGroup in the delta and full sync paths.
     */
    private static void crossCheckGroupMembers(KeycloakSession session, RealmModel realm,
                                               ComponentModel target, ScimClient client,
                                               List<GroupModel> inScopeGroups) {
        debug("crossCheckGroupMembers START target=%s groups=%d", target.getName(), inScopeGroups.size());

        String removeForm = ScimTargetProviderFactory.get(target,
                ScimTargetProviderFactory.CFG_GROUP_MEMBER_REMOVE_FORM,
                ScimMapper.REMOVE_FORM_RFC_PATH_FILTER);

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
            Optional<String> scimGroupIdOpt = resolveScimGroupId(client, target, group.getId(), group.getName());
            if (scimGroupIdOpt.isEmpty()) {
                debug("crossCheck: SCIM group not found for KC group '%s' (id=%s). Skipping.",
                        group.getName(), group.getId());
                continue;
            }
            String scimGroupId = scimGroupIdOpt.get();

            List<String> remoteScimUserIds = client.getGroupMembers(scimGroupId);
            debug("crossCheck: group=%s scimGroupId=%s remote members=%d",
                    group.getName(), scimGroupId, remoteScimUserIds.size());
            if (remoteScimUserIds.isEmpty()) {
                continue;
            }

            Set<String> localScimUserIds = new HashSet<>();
            List<UserModel> groupMembers = session.users().getGroupMembersStream(realm, group).toList();
            for (UserModel member : groupMembers) {
                if (filterGroupName != null && !filterGroupName.isBlank()
                        && !scopedUserIds.contains(member.getId())) {
                    continue;
                }
                String scimUserName = computeScimUserName(target, member);
                Optional<String> scimUserId = resolveScimUserId(client, target, member.getId(), scimUserName);
                scimUserId.ifPresent(localScimUserIds::add);
            }

            for (String remoteId : remoteScimUserIds) {
                if (localScimUserIds.contains(remoteId)) {
                    continue;
                }
                debug("crossCheck: removing excess remote member scimUserId=%s from group=%s target=%s",
                        remoteId, group.getName(), target.getName());
                try {
                    boolean ok = client.patchGroup(scimGroupId,
                            ScimMapper.buildGroupMemberPatch("remove", remoteId, removeForm));
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
    // Deprovision sweep
    // =========================================================================

    /**
     * Deprovisions (deletes) SCIM groups that were previously provisioned by this target
     * but are no longer in scope (their KC group name no longer matches isGroupInScope).
     *
     * A group is considered "previously provisioned" when it still carries at least one
     * GroupMembershipState attribute entry for this target's componentId. Groups that were
     * created in SCIM by other means (no KC state attributes) are never touched.
     *
     * Logic per target:
     *   1. Full-scan all KC realm groups and collect those that have a GroupMembershipState
     *      entry for this target (= were provisioned at some point). This scan is acceptable
     *      because group counts are small (tens to low hundreds).
     *   2. Filter to those where isGroupInScope(target, group.getName()) returns false.
     *   3. For each out-of-scope group:
     *      a. Resolve its SCIM group id via resolveScimGroupId (no upsert).
     *      b. If found remotely: send DELETE /Groups/{scimGroupId}.
     *         On success: call clearGroupState to remove KC attributes.
     *         On failure: log ERROR; leave KC attributes intact (will retry next cycle).
     *      c. If not found remotely: the remote group is already gone. Call
     *         clearGroupState for housekeeping and log INFO.
     *
     * This method must NOT be called from crossCheckGroupMembers or upsertScimGroup.
     * It is a top-level sweep, invoked from runSweep as Step 3.
     *
     * @param componentIdFilter scoped to this target only; always non-null in practice
     *                          (runSweep passes model.getId()).
     */
    public static void deprovisionOutOfScopeGroups(KeycloakSession session, RealmModel realm,
                                                    String componentIdFilter) {
        long start = System.currentTimeMillis();
        debug("=== deprovisionOutOfScopeGroups START realm=%s componentIdFilter=%s ===",
                realm.getName(), componentIdFilter);

        List<ComponentModel> targets = scimTargets(realm, componentIdFilter);
        if (targets.isEmpty()) {
            debug("No matching SCIM targets in realm=%s. Nothing to deprovision.", realm.getName());
            return;
        }

        for (ComponentModel target : targets) {
            if (!"true".equalsIgnoreCase(ScimTargetProviderFactory.get(
                    target, ScimTargetProviderFactory.CFG_SYNC_GROUPS, "false"))) {
                continue;
            }

            String base  = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_BASE_URL, null);
            String token = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_TOKEN, null);
            if (base == null || token == null) {
                err("Target=%s: incomplete config. Skipping deprovision sweep.", target.getName());
                continue;
            }
            ScimClient client = new ScimClient(base, token);

            // Step 1: find all KC groups that carry a GroupMembershipState entry for this target.
            // Full group-stream scan is acceptable: groups are few (tens to low hundreds).
            // Keycloak has no indexed group-attribute search API.
            List<GroupModel> previouslyProvisioned = session.groups()
                    .getGroupsStream(realm)
                    .filter(g -> {
                        List<String> vals = g.getAttributeStream(
                                GroupMembershipState.ATTRIBUTE_NAME).toList();
                        return vals.stream()
                                .map(GroupMembershipState::parse)
                                .filter(Optional::isPresent)
                                .map(Optional::get)
                                .anyMatch(e -> e.componentId().equals(target.getId()));
                    })
                    .collect(Collectors.toList());

            // Step 2: keep only those no longer in scope.
            List<GroupModel> outOfScope = previouslyProvisioned.stream()
                    .filter(g -> !isGroupInScope(target, g.getName()))
                    .collect(Collectors.toList());

            if (outOfScope.isEmpty()) {
                debug("Target=%s: no out-of-scope provisioned group(s) found.", target.getName());
                continue;
            }
            debug("Target=%s: %d out-of-scope group(s) to deprovision.", target.getName(), outOfScope.size());

            // Step 3: delete each out-of-scope group from SCIM.
            for (GroupModel group : outOfScope) {
                Optional<String> scimGroupId = resolveScimGroupId(
                        client, target, group.getId(), group.getName());

                if (scimGroupId.isEmpty()) {
                    // Group already gone remotely; clean up KC state only.
                    info("Target=%s: SCIM group for KC group '%s' (id=%s) not found remotely. "
                            + "Cleaning up KC attributes only.",
                            target.getName(), group.getName(), group.getId());
                    clearGroupState(group, target.getId());
                    continue;
                }

                debug("Calling client.deleteGroup scimGroupId=%s group='%s' target=%s",
                        scimGroupId.get(), group.getName(), target.getName());
                try {
                    boolean ok = client.deleteGroup(scimGroupId.get());
                    if (ok) {
                        info("DEPROVISIONED group='%s' scimGroupId=%s target=%s -> DELETE OK",
                                group.getName(), scimGroupId.get(), target.getName());
                        clearGroupState(group, target.getId());
                    } else {
                        err("DEPROVISION FAILED group='%s' scimGroupId=%s target=%s. Will retry next cycle.",
                                group.getName(), scimGroupId.get(), target.getName());
                        // KC attributes left intact so the group is retried on the next cycle.
                    }
                } catch (Exception e) {
                    err("DEPROVISION EXCEPTION group='%s' scimGroupId=%s target=%s: %s",
                            group.getName(), scimGroupId.get(), target.getName(), e.getMessage());
                }
            }
        }

        debug("=== deprovisionOutOfScopeGroups DONE realm=%s durationMs=%d ===",
                realm.getName(), System.currentTimeMillis() - start);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Resolves the SCIM id for the given KC group, creating the group in SCIM if it does
     * not exist yet (upsert semantics). Returns empty only if creation fails or the id
     * cannot be resolved after a successful create.
     *
     * The event-driven path (ScimEventListenerProvider) handles groups created via the KC
     * admin console, but LDAP sync never fires those events. Groups that exist in LDAP but
     * have not yet been provisioned to SCIM must therefore be auto-created here on first
     * encounter.
     *
     * Callers: processPendingGroupMembershipChanges and processFullGroupSync.
     * crossCheckGroupMembers must NOT call this method -- it only removes excess remote
     * members and has no business creating new groups.
     */
    private static Optional<String> upsertScimGroup(ScimClient client, ComponentModel target,
                                                     GroupModel group) {
        Optional<String> scimGroupId = resolveScimGroupId(client, target, group.getId(), group.getName());
        if (scimGroupId.isPresent()) {
            return scimGroupId;
        }

        // Group not found in SCIM -- create it now.
        info("Target=%s: SCIM group not found for KC group '%s' (id=%s). Auto-creating.",
                target.getName(), group.getName(), group.getId());
        String payload = ScimMapper.buildCreateGroup(group.getName(), group.getId());
        debug("Calling client.createGroup group=%s target=%s payload=%s",
                group.getName(), target.getName(), payload);
        boolean created = client.createGroup(payload);
        if (!created) {
            err("Target=%s: Failed to auto-create SCIM group for KC group '%s' (id=%s). Skipping.",
                    target.getName(), group.getName(), group.getId());
            return Optional.empty();
        }

        // Re-resolve after creation to get the new SCIM id.
        scimGroupId = resolveScimGroupId(client, target, group.getId(), group.getName());
        if (scimGroupId.isEmpty()) {
            err("Target=%s: Auto-created SCIM group for KC group '%s' (id=%s) but could not resolve id. Skipping.",
                    target.getName(), group.getName(), group.getId());
        } else {
            info("Target=%s: Auto-created SCIM group '%s' -> scimGroupId=%s",
                    target.getName(), group.getName(), scimGroupId.get());
        }
        return scimGroupId;
    }

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
            String filterGroupName = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
            if (filterGroupName == null || filterGroupName.isBlank()) return List.of();
            return session.groups().searchForGroupByNameStream(realm, filterGroupName, true, null, null)
                    .collect(Collectors.toList());
        }
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
     * Behaviour is governed by CFG_LOOKUP_STRATEGY on the given target:
     *
     *   "externalId first" (default):
     *     1. Query by externalId. If exactly one result is returned, use it.
     *     2. If zero results: not found by externalId, fall through to displayName.
     *     3. If more than one result: ambiguous (server-side data issue). Do not pick an
     *        arbitrary match -- fall back to displayName and log a warning.
     *
     *   "name only":
     *     Skip the externalId HTTP call entirely. Go straight to displayName lookup.
     *     Use this when the SCIM server ignores the externalId filter.
     */
    private static Optional<String> resolveScimGroupId(ScimClient client, ComponentModel target,
                                                        String externalId, String displayName) {
        debug("resolveScimGroupId CALL externalId=%s displayName=%s", externalId, displayName);

        String strategy = ScimTargetProviderFactory.get(target,
                ScimTargetProviderFactory.CFG_LOOKUP_STRATEGY,
                ScimTargetProviderFactory.LOOKUP_STRATEGY_EXTERNAL_ID_FIRST);

        Optional<String> id = Optional.empty();

        if (!ScimTargetProviderFactory.LOOKUP_STRATEGY_NAME_ONLY.equals(strategy)
                && externalId != null && !externalId.isBlank()) {
            ScimClient.ScimLookupResult r = client.findGroupByExternalId(externalId);
            if (r.totalResults() == 1) {
                id = r.id();
            } else if (r.totalResults() > 1) {
                debug("resolveScimGroupId: externalId=%s returned %d results (ambiguous), falling back to displayName",
                        externalId, r.totalResults());
            }
            // totalResults == 0: not found, fall through to displayName
        }

        if (id.isEmpty() && displayName != null && !displayName.isBlank()) {
            if (ScimTargetProviderFactory.LOOKUP_STRATEGY_NAME_ONLY.equals(strategy)) {
                debug("resolveScimGroupId: strategy=name only, going straight to displayName=%s", displayName);
            } else {
                debug("resolveScimGroupId: externalId lookup empty, falling back to displayName=%s", displayName);
            }
            id = client.findGroupIdByDisplayName(displayName);
        }

        debug("resolveScimGroupId RESULT externalId=%s displayName=%s strategy=%s -> %s",
                externalId, displayName, strategy, id.orElse("<none>"));
        return id;
    }

    /**
     * Resolve the SCIM user id for a Keycloak user.
     *
     * Behaviour is governed by CFG_LOOKUP_STRATEGY on the given target:
     *
     *   "externalId first" (default):
     *     1. Query by externalId. If exactly one result is returned, use it.
     *     2. If the result is empty or ambiguous (totalResults != 1), fall back to userName.
     *
     *   "name only":
     *     Skip the externalId HTTP call entirely. Go straight to userName lookup.
     *     Use this when the SCIM server ignores the externalId filter.
     */
    private static Optional<String> resolveScimUserId(ScimClient client, ComponentModel target,
                                                       String externalId, String scimUserName) {
        debug("resolveScimUserId CALL externalId=%s scimUserName=%s", externalId, scimUserName);

        String strategy = ScimTargetProviderFactory.get(target,
                ScimTargetProviderFactory.CFG_LOOKUP_STRATEGY,
                ScimTargetProviderFactory.LOOKUP_STRATEGY_EXTERNAL_ID_FIRST);

        Optional<String> id = Optional.empty();

        if (!ScimTargetProviderFactory.LOOKUP_STRATEGY_NAME_ONLY.equals(strategy)
                && externalId != null && !externalId.isBlank()) {
            id = client.findUserIdByExternalId(externalId);
        }

        if (id.isEmpty() && scimUserName != null && !scimUserName.isBlank()) {
            if (ScimTargetProviderFactory.LOOKUP_STRATEGY_NAME_ONLY.equals(strategy)) {
                debug("resolveScimUserId: strategy=name only, going straight to userName=%s", scimUserName);
            } else {
                debug("resolveScimUserId: externalId lookup empty, falling back to userName=%s", scimUserName);
            }
            id = client.findUserIdByUserName(scimUserName);
        }

        debug("resolveScimUserId RESULT externalId=%s scimUserName=%s strategy=%s -> %s",
                externalId, scimUserName, strategy, id.orElse("<none>"));
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
