package es.diegosr.keycloak_scim_outbound.ldapsync;

import es.diegosr.keycloak_scim_outbound.http.ScimClient;
import es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory;
import es.diegosr.keycloak_scim_outbound.util.ScimMapper;
import org.jboss.logging.Logger;
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
import java.util.function.BiFunction;
import java.util.stream.Collectors;

/**
 * Flushes pending SCIM /Groups LDAP-driven membership changes to the configured SCIM targets.
 * Parallel to ScimMembershipSync (which handles /Users).
 *
 * Two primary entry points:
 *   processPendingGroupMembershipChanges -- delta flush; only groups marked pending
 *   processFullGroupSync                 -- full PATCH replace for all in-scope groups
 *
 * Called from ScimTargetProviderFactory.runSweep() after user sync has completed.
 * User sync always runs first so every in-scope user already has a SCIM ID by the time
 * group sync resolves member IDs.
 *
 * Group attributes (GroupMembershipState.*) are written directly on GroupModel --
 * groups are realm-local, not federated storage, so no UserStoragePrivateUtil is needed.
 *
 * STATE INVARIANT (issues 2 and 4):
 * GroupMembershipState attributes are permanent lifecycle markers. They must never be
 * bulk-cleared by a sync run. clearGroupState is called ONLY from deprovisionOutOfScopeGroups
 * after a successful remote DELETE -- it must not be called from any sync path.
 * The pending flag (scimGroupSync.pending) is cleared when no non-SENT entries remain.
 *
 * RESOLUTION SAFETY (issue 3):
 * processFullGroupSync and crossCheckGroupMembers abort their PATCH replace / removal
 * loop for a given group if any member's SCIM user ID cannot be resolved. A transient
 * lookup failure must never trigger a destructive remote operation.
 */
public final class ScimGroupSync {

    private static final Logger LOG = Logger.getLogger(ScimGroupSync.class);

    /**
     * Mode values for CFG_LDAP_GROUP_PROV_MODE.
     * Must stay in sync with the list options in ScimTargetProviderFactory.PROPS.
     */
    public static final String MODE_DELTA_ONLY        = "Delta (add members)";
    public static final String MODE_DELTA_DEPROVISION = "Delta (add and remove members)";
    public static final String MODE_FULL              = "Full";

    /**
     * Package-private factory for ScimClient instances.
     * Default: ScimClient::new. Tests may replace this with a lambda returning a mock.
     * Reset to ScimClient::new after each test to avoid cross-test pollution.
     */
    static BiFunction<String, String, ScimClient> clientFactory = ScimClient::new;

    private ScimGroupSync() {}

    // =========================================================================
    // Delta flush
    // =========================================================================

    /**
     * Process only groups that have a pending entry for the given target.
     *
     * Mode governs which states are flushed and whether the cross-check runs:
     *   MODE_DELTA_ONLY        -- flush NEW_ADDED only; no cross-check
     *   MODE_DELTA_DEPROVISION -- flush NEW_ADDED + NEW_DELETED; then run crossCheckGroupMembers
     *
     * MODE_FULL is never routed here; callers must use processFullGroupSync instead.
     *
     * @param componentIdFilter if non-null, scope to that target only.
     * @param mode              value of CFG_LDAP_GROUP_PROV_MODE as read by runSweep.
     */
    public static void processPendingGroupMembershipChanges(KeycloakSession session, RealmModel realm,
                                                            String componentIdFilter, String mode) {
        long start = System.currentTimeMillis();
        LOG.infof("=== processPendingGroupMembershipChanges START realm=%s componentIdFilter=%s mode=%s ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter, mode);

        List<ComponentModel> targets = scimTargets(realm, componentIdFilter);
        if (targets.isEmpty()) {
            LOG.debugf("No matching SCIM targets in realm=%s (filter=%s). Nothing to do.",
                    realm.getName(), componentIdFilter);
            return;
        }

        boolean flushDeletes = MODE_DELTA_DEPROVISION.equals(mode);
        boolean runCrossCheck = MODE_DELTA_DEPROVISION.equals(mode);

        int groupsProcessed = 0;
        int pushedAdds      = 0;
        int pushedRemoves   = 0;
        int failures        = 0;

        for (ComponentModel target : targets) {
            if (!"true".equalsIgnoreCase(ScimTargetProviderFactory.get(
                    target, ScimTargetProviderFactory.CFG_SYNC_GROUPS, "false"))) {
                continue;
            }

            String base  = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_BASE_URL, null);
            String token = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_TOKEN, null);
            if (base == null || token == null) {
                LOG.errorf("Target=%s incomplete config (baseUrl/token). Skipping group sync.", target.getName());
                continue;
            }
            ScimClient client = clientFactory.apply(base, token);
            String removeForm = ScimTargetProviderFactory.get(target,
                    ScimTargetProviderFactory.CFG_GROUP_MEMBER_REMOVE_FORM,
                    ScimMapper.REMOVE_FORM_RFC_PATH_FILTER);

            List<GroupModel> inScopeGroups = resolveInScopeGroups(session, realm, target);
            LOG.debugf("Target=%s: %d in-scope group(s) total.", target.getName(), inScopeGroups.size());

            List<GroupModel> candidates = inScopeGroups.stream()
                    .filter(g -> {
                        List<String> pending = g.getAttributeStream(
                                GroupMembershipState.PENDING_ATTRIBUTE_NAME).toList();
                        return pending.contains(GroupMembershipState.pendingValue(target.getId()));
                    })
                    .collect(Collectors.toList());

            LOG.debugf("Target=%s: %d candidate group(s) with pending entries.", target.getName(), candidates.size());

            for (GroupModel group : candidates) {
                groupsProcessed++;
                List<String> stateValues = new ArrayList<>(
                        group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME).toList());

                Optional<String> scimGroupId = upsertScimGroup(client, target, group);
                if (scimGroupId.isEmpty()) {
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
                    if (entry.state() == GroupMembershipState.State.NEW_DELETED && !flushDeletes) {
                        LOG.debugf("Mode=%s: skipping NEW_DELETED group=%s userId=%s target=%s",
                                mode, group.getName(), entry.userId(), target.getName());
                        continue;
                    }

                    UserModel kcUser = session.users().getUserById(realm, entry.userId());
                    String scimUserName = kcUser != null ? computeScimUserName(target, kcUser) : null;
                    Optional<String> scimUserId = resolveScimUserId(client, target, entry.userId(), scimUserName);

                    if (scimUserId.isEmpty()) {
                        LOG.errorf("Target=%s: SCIM user not found for userId=%s (group=%s). Skipping entry.",
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
                                updatedValues.add(new GroupMembershipState(
                                        entry.componentId(), entry.userId(),
                                        GroupMembershipState.State.SENT).toValue());
                                groupChanged = true;
                                pushedAdds++;
                                LOG.infof("PUSHED ADD group=%s userId=%s target=%s -> SENT",
                                        group.getName(), entry.userId(), target.getName());
                            } else {
                                failures++;
                                LOG.errorf("FAILED ADD group=%s userId=%s target=%s. Will retry.",
                                        group.getName(), entry.userId(), target.getName());
                            }
                        } else if (entry.state() == GroupMembershipState.State.NEW_DELETED) {
                            boolean ok = client.patchGroup(scimGroupId.get(),
                                    ScimMapper.buildGroupMemberPatch("remove", scimUserId.get(), removeForm));
                            if (ok) {
                                updatedValues.remove(raw);
                                groupChanged = true;
                                pushedRemoves++;
                                LOG.infof("PUSHED REMOVE group=%s userId=%s target=%s -> entry removed",
                                        group.getName(), entry.userId(), target.getName());
                            } else {
                                failures++;
                                LOG.errorf("FAILED REMOVE group=%s userId=%s target=%s. Will retry.",
                                        group.getName(), entry.userId(), target.getName());
                            }
                        }
                    } catch (Exception e) {
                        failures++;
                        LOG.errorf("EXCEPTION group=%s userId=%s target=%s state=%s: %s",
                                group.getName(), entry.userId(), target.getName(), entry.state(), e.getMessage());
                    }
                }

                if (groupChanged) {
                    writeGroupState(group, target.getId(), updatedValues);
                }
            }

            if (runCrossCheck) {
                crossCheckGroupMembers(session, realm, target, client, inScopeGroups);
            }
        }

        LOG.infof("=== processPendingGroupMembershipChanges DONE realm=%s componentIdFilter=%s mode=%s: "
                        + "groupsProcessed=%d pushedAdds=%d pushedRemoves=%d failures=%d durationMs=%d ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter, mode,
                groupsProcessed, pushedAdds, pushedRemoves, failures,
                System.currentTimeMillis() - start);
    }

    // =========================================================================
    // Full sync
    // =========================================================================

    /**
     * Full sync: send a complete PATCH replace for all in-scope groups.
     * Called by sync() (Synchronize all) and by syncSince() when CFG_LDAP_GROUP_PROV_MODE=Full.
     *
     * STATE INVARIANT: GroupMembershipState attributes survive this call.
     * On success the state for members included in the replace is transitioned to SENT.
     * NEW_DELETED entries for members excluded from the replace are removed (removal was
     * implicit in the replace). The pending flag is cleared when no non-SENT entries remain.
     * clearGroupState is NOT called here.
     *
     * RESOLUTION SAFETY: if any member's SCIM user ID cannot be resolved, the PATCH replace
     * for that group is aborted entirely to prevent accidental removals.
     *
     * @param componentIdFilter if non-null, scope to that target only.
     */
    public static void processFullGroupSync(KeycloakSession session, RealmModel realm,
                                            String componentIdFilter) {
        long start = System.currentTimeMillis();
        LOG.infof("=== processFullGroupSync START realm=%s componentIdFilter=%s ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter);

        List<ComponentModel> targets = scimTargets(realm, componentIdFilter);
        if (targets.isEmpty()) {
            LOG.debugf("No matching SCIM targets in realm=%s (filter=%s). Nothing to do.",
                    realm.getName(), componentIdFilter);
            return;
        }

        int groupsProcessed = 0;
        int failures        = 0;

        for (ComponentModel target : targets) {
            if (!"true".equalsIgnoreCase(ScimTargetProviderFactory.get(
                    target, ScimTargetProviderFactory.CFG_SYNC_GROUPS, "false"))) {
                continue;
            }

            String base  = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_BASE_URL, null);
            String token = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_TOKEN, null);
            if (base == null || token == null) {
                LOG.errorf("Target=%s incomplete config (baseUrl/token). Skipping full group sync.", target.getName());
                continue;
            }
            ScimClient client = clientFactory.apply(base, token);

            List<GroupModel> inScopeGroups = resolveInScopeGroups(session, realm, target);
            LOG.debugf("Target=%s: %d in-scope group(s) for full sync.", target.getName(), inScopeGroups.size());

            // Collect filter-group member IDs for the scope intersection check.
            String filterGroupName = ScimTargetProviderFactory.get(
                    target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
            Set<String> scopedUserIds = new HashSet<>();
            if (filterGroupName != null && !filterGroupName.isBlank()) {
                session.groups().searchForGroupByNameStream(realm, filterGroupName, true, null, null)
                        .findFirst()
                        .ifPresent(fg -> session.users().getGroupMembersStream(realm, fg)
                                .forEach(u -> scopedUserIds.add(u.getId())));
            }

            for (GroupModel group : inScopeGroups) {
                groupsProcessed++;

                Optional<String> scimGroupId = upsertScimGroup(client, target, group);
                if (scimGroupId.isEmpty()) {
                    failures++;
                    continue;
                }

                // Resolve SCIM user IDs for all in-scope members.
                // Abort the replace entirely if any lookup fails (issue 3).
                List<UserModel> groupMembers = session.users()
                        .getGroupMembersStream(realm, group).toList();

                List<String> scimMemberIds = new ArrayList<>();
                boolean resolutionComplete = true;

                for (UserModel member : groupMembers) {
                    if (filterGroupName != null && !filterGroupName.isBlank()
                            && !scopedUserIds.contains(member.getId())) {
                        continue;
                    }
                    String scimUserName = computeScimUserName(target, member);
                    Optional<String> scimUserId = resolveScimUserId(
                            client, target, member.getId(), scimUserName);
                    if (scimUserId.isEmpty()) {
                        LOG.errorf("Target=%s: could not resolve SCIM ID for userId=%s in group=%s. "
                                + "Aborting replace for this group to prevent invalid removals.",
                                target.getName(), member.getId(), group.getName());
                        resolutionComplete = false;
                        break;
                    }
                    scimMemberIds.add(scimUserId.get());
                }

                if (!resolutionComplete) {
                    failures++;
                    continue;
                }

                try {
                    LOG.debugf("patchGroup(replace) group=%s scimGroupId=%s target=%s members=%d",
                            group.getName(), scimGroupId.get(), target.getName(), scimMemberIds.size());
                    boolean ok = client.patchGroup(scimGroupId.get(),
                            ScimMapper.buildGroupMemberReplace(scimMemberIds));
                    if (ok) {
                        LOG.infof("FULL SYNC group=%s target=%s members=%d -> OK",
                                group.getName(), target.getName(), scimMemberIds.size());
                        // Transition state: mark resolved members as SENT, drop stale deletes.
                        transitionGroupStateAfterFullSync(group, target.getId(),
                                scimMemberIds, groupMembers, scopedUserIds, filterGroupName);
                    } else {
                        failures++;
                        LOG.errorf("FULL SYNC group=%s target=%s FAILED.", group.getName(), target.getName());
                    }
                } catch (Exception e) {
                    failures++;
                    LOG.errorf("FULL SYNC EXCEPTION group=%s target=%s: %s",
                            group.getName(), target.getName(), e.getMessage());
                }
            }
        }

        LOG.infof("=== processFullGroupSync DONE realm=%s componentIdFilter=%s: "
                        + "groupsProcessed=%d failures=%d durationMs=%d ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter,
                groupsProcessed, failures, System.currentTimeMillis() - start);
    }

    /**
     * Updates GroupMembershipState after a successful full PATCH replace.
     *
     * For each member included in the replace (i.e. their SCIM ID is in scimMemberIds):
     *   - Replace any existing entry (NEW_ADDED, SENT, or absent) with SENT.
     * For each member excluded from the replace (out of filter-group scope):
     *   - Remove any NEW_DELETED entry (removal was implicit in the replace).
     *   - Leave SENT entries intact -- they remain valid.
     * The pending flag is cleared when no non-SENT entries remain.
     *
     * scimMemberIds is parallel to the resolved members list but we work from the
     * full groupMembers list to determine who was included vs excluded.
     */
    private static void transitionGroupStateAfterFullSync(
            GroupModel group, String componentId,
            List<String> scimMemberIds,
            List<UserModel> groupMembers,
            Set<String> scopedUserIds,
            String filterGroupName) {

        // Build the set of KC user IDs that were included in the replace.
        Set<String> includedUserIds = new HashSet<>();
        for (UserModel m : groupMembers) {
            if (filterGroupName != null && !filterGroupName.isBlank()
                    && !scopedUserIds.contains(m.getId())) {
                continue;
            }
            includedUserIds.add(m.getId());
        }

        List<String> current = new ArrayList<>(
                group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME).toList());
        List<String> updated = new ArrayList<>();

        // Preserve entries for other targets unchanged.
        for (String raw : current) {
            Optional<GroupMembershipState> parsed = GroupMembershipState.parse(raw);
            if (parsed.isEmpty() || !parsed.get().componentId().equals(componentId)) {
                updated.add(raw);
            }
            // Entries for this target are rebuilt below.
        }

        // Re-add entries for this target with correct post-sync state.
        // Included members -> SENT. Excluded members -> remove NEW_DELETED, keep SENT.
        Set<String> wroteUserIds = new HashSet<>();
        for (String raw : current) {
            Optional<GroupMembershipState> parsed = GroupMembershipState.parse(raw);
            if (parsed.isEmpty() || !parsed.get().componentId().equals(componentId)) continue;
            GroupMembershipState entry = parsed.get();
            String uid = entry.userId();

            if (includedUserIds.contains(uid)) {
                // Was included in the replace -> SENT.
                if (!wroteUserIds.contains(uid)) {
                    updated.add(new GroupMembershipState(componentId, uid,
                            GroupMembershipState.State.SENT).toValue());
                    wroteUserIds.add(uid);
                }
            } else {
                // Not included (out of scope). Drop NEW_DELETED (implicit); keep SENT.
                if (entry.state() == GroupMembershipState.State.SENT) {
                    updated.add(raw);
                }
                // NEW_DELETED dropped intentionally; NEW_ADDED left: should not occur
                // for out-of-scope members but preserve defensively.
                if (entry.state() == GroupMembershipState.State.NEW_ADDED) {
                    updated.add(raw);
                }
            }
        }

        // Add SENT entries for included members that had no prior state entry.
        for (UserModel m : groupMembers) {
            if (filterGroupName != null && !filterGroupName.isBlank()
                    && !scopedUserIds.contains(m.getId())) {
                continue;
            }
            if (!wroteUserIds.contains(m.getId())) {
                updated.add(new GroupMembershipState(componentId, m.getId(),
                        GroupMembershipState.State.SENT).toValue());
            }
        }

        writeGroupState(group, componentId, updated);
    }

    // =========================================================================
    // Cross-check
    // =========================================================================

    /**
     * Verifies that the remote SCIM group member list matches the local Keycloak state for
     * each in-scope group. Removes any remote members absent from the local KC group
     * (intersected with the CFG_FILTER_GROUP scope boundary).
     *
     * Only called in MODE_DELTA_DEPROVISION mode, after the pending-entry flush.
     * No adds are performed here.
     *
     * RESOLUTION SAFETY (issue 3): if any member's SCIM user ID cannot be resolved, the
     * removal loop for that group is aborted entirely. A transient lookup failure must not
     * cause valid remote members to be removed.
     *
     * This method must NOT auto-create missing SCIM groups. Groups not found remotely are
     * silently skipped.
     */
    private static void crossCheckGroupMembers(KeycloakSession session, RealmModel realm,
                                               ComponentModel target, ScimClient client,
                                               List<GroupModel> inScopeGroups) {
        LOG.debugf("crossCheckGroupMembers START target=%s groups=%d",
                target.getName(), inScopeGroups.size());

        String removeForm = ScimTargetProviderFactory.get(target,
                ScimTargetProviderFactory.CFG_GROUP_MEMBER_REMOVE_FORM,
                ScimMapper.REMOVE_FORM_RFC_PATH_FILTER);

        String filterGroupName = ScimTargetProviderFactory.get(
                target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
        Set<String> scopedUserIds = new HashSet<>();
        if (filterGroupName != null && !filterGroupName.isBlank()) {
            session.groups().searchForGroupByNameStream(realm, filterGroupName, true, null, null)
                    .findFirst()
                    .ifPresent(fg -> session.users().getGroupMembersStream(realm, fg)
                            .forEach(u -> scopedUserIds.add(u.getId())));
        }

        int removedTotal  = 0;
        int failuresTotal = 0;

        for (GroupModel group : inScopeGroups) {
            Optional<String> scimGroupIdOpt = resolveScimGroupId(
                    client, target, group.getId(), group.getName());
            if (scimGroupIdOpt.isEmpty()) {
                LOG.debugf("crossCheck: SCIM group not found for KC group '%s' (id=%s). Skipping.",
                        group.getName(), group.getId());
                continue;
            }
            String scimGroupId = scimGroupIdOpt.get();

            List<String> remoteScimUserIds = client.getGroupMembers(scimGroupId);
            if (remoteScimUserIds.isEmpty()) continue;

            // Resolve local SCIM user IDs. Abort removals for this group if any lookup fails.
            List<UserModel> groupMembers = session.users()
                    .getGroupMembersStream(realm, group).toList();
            Set<String> localScimUserIds = new HashSet<>();
            boolean resolutionComplete = true;

            for (UserModel member : groupMembers) {
                if (filterGroupName != null && !filterGroupName.isBlank()
                        && !scopedUserIds.contains(member.getId())) {
                    continue;
                }
                String scimUserName = computeScimUserName(target, member);
                Optional<String> scimUserId = resolveScimUserId(
                        client, target, member.getId(), scimUserName);
                if (scimUserId.isEmpty()) {
                    LOG.errorf("crossCheck: could not resolve SCIM ID for userId=%s in group=%s target=%s. "
                            + "Aborting removal loop for this group to prevent invalid removals.",
                            member.getId(), group.getName(), target.getName());
                    resolutionComplete = false;
                    break;
                }
                localScimUserIds.add(scimUserId.get());
            }

            if (!resolutionComplete) {
                failuresTotal++;
                continue;
            }

            for (String remoteId : remoteScimUserIds) {
                if (localScimUserIds.contains(remoteId)) continue;
                try {
                    boolean ok = client.patchGroup(scimGroupId,
                            ScimMapper.buildGroupMemberPatch("remove", remoteId, removeForm));
                    if (ok) {
                        removedTotal++;
                        LOG.infof("CROSS-CHECK REMOVE group=%s scimUserId=%s target=%s -> OK",
                                group.getName(), remoteId, target.getName());
                    } else {
                        failuresTotal++;
                        LOG.errorf("CROSS-CHECK REMOVE group=%s scimUserId=%s target=%s -> FAILED.",
                                group.getName(), remoteId, target.getName());
                    }
                } catch (Exception e) {
                    failuresTotal++;
                    LOG.errorf("CROSS-CHECK REMOVE EXCEPTION group=%s scimUserId=%s target=%s: %s",
                            group.getName(), remoteId, target.getName(), e.getMessage());
                }
            }
        }

        LOG.debugf("crossCheckGroupMembers DONE target=%s removedTotal=%d failuresTotal=%d",
                target.getName(), removedTotal, failuresTotal);
    }

    // =========================================================================
    // Deprovision sweep
    // =========================================================================

    /**
     * Deprovisions (deletes) SCIM groups that were previously provisioned by this target
     * but are no longer in scope (their KC group name no longer matches isGroupInScope).
     *
     * A group is considered "previously provisioned" when it carries at least one
     * GroupMembershipState attribute entry for this target's componentId. Groups created
     * in SCIM by other means (no KC state attributes) are never touched.
     *
     * clearGroupState is called here -- and ONLY here -- after a successful remote DELETE.
     *
     * @param componentIdFilter always non-null in practice (runSweep passes model.getId()).
     */
    public static void deprovisionOutOfScopeGroups(KeycloakSession session, RealmModel realm,
                                                    String componentIdFilter) {
        long start = System.currentTimeMillis();
        LOG.infof("=== deprovisionOutOfScopeGroups START realm=%s componentIdFilter=%s ===",
                realm.getName(), componentIdFilter);

        List<ComponentModel> targets = scimTargets(realm, componentIdFilter);
        if (targets.isEmpty()) {
            LOG.debugf("No matching SCIM targets in realm=%s. Nothing to deprovision.", realm.getName());
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
                LOG.errorf("Target=%s: incomplete config. Skipping deprovision sweep.", target.getName());
                continue;
            }
            ScimClient client = clientFactory.apply(base, token);

            // Full group-stream scan is acceptable: group counts are small (tens to low hundreds)
            // and Keycloak has no indexed group-attribute search API.
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

            List<GroupModel> outOfScope = previouslyProvisioned.stream()
                    .filter(g -> !isGroupInScope(target, g.getName()))
                    .collect(Collectors.toList());

            if (outOfScope.isEmpty()) {
                LOG.debugf("Target=%s: no out-of-scope provisioned group(s) found.", target.getName());
                continue;
            }
            LOG.debugf("Target=%s: %d out-of-scope group(s) to deprovision.", target.getName(), outOfScope.size());

            for (GroupModel group : outOfScope) {
                Optional<String> scimGroupId = resolveScimGroupId(
                        client, target, group.getId(), group.getName());

                if (scimGroupId.isEmpty()) {
                    LOG.infof("Target=%s: SCIM group for KC group '%s' (id=%s) not found remotely. "
                            + "Cleaning up KC attributes only.",
                            target.getName(), group.getName(), group.getId());
                    clearGroupState(group, target.getId());
                    continue;
                }

                try {
                    boolean ok = client.deleteGroup(scimGroupId.get());
                    if (ok) {
                        LOG.infof("DEPROVISIONED group='%s' scimGroupId=%s target=%s -> DELETE OK",
                                group.getName(), scimGroupId.get(), target.getName());
                        // clearGroupState called ONLY here, after a confirmed remote DELETE.
                        clearGroupState(group, target.getId());
                    } else {
                        LOG.errorf("DEPROVISION FAILED group='%s' scimGroupId=%s target=%s. Will retry next cycle.",
                                group.getName(), scimGroupId.get(), target.getName());
                    }
                } catch (Exception e) {
                    LOG.errorf("DEPROVISION EXCEPTION group='%s' scimGroupId=%s target=%s: %s",
                            group.getName(), scimGroupId.get(), target.getName(), e.getMessage());
                }
            }
        }

        LOG.infof("=== deprovisionOutOfScopeGroups DONE realm=%s durationMs=%d ===",
                realm.getName(), System.currentTimeMillis() - start);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Resolves the SCIM id for the given KC group, creating the group in SCIM if it does
     * not exist yet (upsert semantics).
     *
     * LDAP sync never fires GROUP_CREATE admin events, so groups originating from LDAP are
     * auto-created here on first encounter.
     *
     * crossCheckGroupMembers must NOT call this method.
     */
    private static Optional<String> upsertScimGroup(ScimClient client, ComponentModel target,
                                                     GroupModel group) {
        Optional<String> scimGroupId = resolveScimGroupId(client, target, group.getId(), group.getName());
        if (scimGroupId.isPresent()) {
            return scimGroupId;
        }

        LOG.infof("Target=%s: SCIM group not found for KC group '%s' (id=%s). Auto-creating.",
                target.getName(), group.getName(), group.getId());
        boolean created = client.createGroup(ScimMapper.buildCreateGroup(group.getName(), group.getId()));
        if (!created) {
            LOG.errorf("Target=%s: Failed to auto-create SCIM group for KC group '%s' (id=%s). Skipping.",
                    target.getName(), group.getName(), group.getId());
            return Optional.empty();
        }

        scimGroupId = resolveScimGroupId(client, target, group.getId(), group.getName());
        if (scimGroupId.isEmpty()) {
            LOG.errorf("Target=%s: Auto-created SCIM group for KC group '%s' but could not resolve id. Skipping.",
                    target.getName(), group.getName());
        } else {
            LOG.infof("Target=%s: Auto-created SCIM group '%s' -> scimGroupId=%s",
                    target.getName(), group.getName(), scimGroupId.get());
        }
        return scimGroupId;
    }

    /**
     * Returns true if the given group name is in scope for SCIM /Groups sync on this target.
     *
     * When CFG_SYNC_GROUPS_FILTER_REGEX is false (default):
     *   CFG_SYNC_GROUPS_FILTER is treated as a comma-separated list of exact group names.
     *   Empty -> fall back to CFG_FILTER_GROUP (single exact match).
     *
     * When CFG_SYNC_GROUPS_FILTER_REGEX is true:
     *   CFG_SYNC_GROUPS_FILTER is treated as a Java regex.
     *   PatternSyntaxException is caught and logged as ERROR, returning false.
     *
     * groupName=null always returns false.
     */
    static boolean isGroupInScope(ComponentModel t, String groupName) {
        if (groupName == null) return false;

        String filter = ScimTargetProviderFactory.get(t, ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER, null);
        boolean useRegex = "true".equalsIgnoreCase(ScimTargetProviderFactory.get(
                t, ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER_REGEX, "false"));

        if (filter == null || filter.isBlank()) {
            // No filter set: fall back to single CFG_FILTER_GROUP exact match.
            String filterGroup = ScimTargetProviderFactory.get(t, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
            return groupName.equals(filterGroup);
        }

        if (useRegex) {
            try {
                return groupName.matches(filter);
            } catch (java.util.regex.PatternSyntaxException e) {
                LOG.errorf("Invalid CFG_SYNC_GROUPS_FILTER regex '%s': %s", filter, e.getMessage());
                return false;
            }
        }

        // Comma-delimited exact match (default).
        for (String part : filter.split(",")) {
            if (groupName.equals(part.trim())) return true;
        }
        return false;
    }

    /**
     * Returns all KC groups that are in scope for SCIM /Groups sync on this target.
     *
     * When CFG_SYNC_GROUPS_FILTER_REGEX is false (default):
     *   Parses CFG_SYNC_GROUPS_FILTER as a comma-separated list and looks up each name.
     *   Empty filter -> single lookup of CFG_FILTER_GROUP.
     *
     * When CFG_SYNC_GROUPS_FILTER_REGEX is true:
     *   Streams all realm groups and retains those matching the regex.
     */
    private static List<GroupModel> resolveInScopeGroups(KeycloakSession session, RealmModel realm,
                                                          ComponentModel target) {
        String filter = ScimTargetProviderFactory.get(
                target, ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER, null);
        boolean useRegex = "true".equalsIgnoreCase(ScimTargetProviderFactory.get(
                target, ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER_REGEX, "false"));

        if (filter == null || filter.isBlank()) {
            String filterGroupName = ScimTargetProviderFactory.get(
                    target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
            if (filterGroupName == null || filterGroupName.isBlank()) return List.of();
            return session.groups()
                    .searchForGroupByNameStream(realm, filterGroupName, true, null, null)
                    .collect(Collectors.toList());
        }

        if (useRegex) {
            return session.groups().getGroupsStream(realm)
                    .filter(g -> {
                        try {
                            return g.getName() != null && g.getName().matches(filter);
                        } catch (java.util.regex.PatternSyntaxException e) {
                            LOG.errorf("Invalid CFG_SYNC_GROUPS_FILTER regex '%s': %s",
                                    filter, e.getMessage());
                            return false;
                        }
                    })
                    .collect(Collectors.toList());
        }

        // Comma-delimited: look up each name individually.
        List<GroupModel> result = new ArrayList<>();
        for (String part : filter.split(",")) {
            String name = part.trim();
            if (!name.isEmpty()) {
                session.groups()
                        .searchForGroupByNameStream(realm, name, true, null, null)
                        .forEach(result::add);
            }
        }
        return result;
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
     * Governed by CFG_LOOKUP_STRATEGY:
     *   "externalId first" (default): try externalId; if zero or ambiguous, fall back to displayName.
     *   "name only": skip the externalId HTTP call; go straight to displayName.
     */
    private static Optional<String> resolveScimGroupId(ScimClient client, ComponentModel target,
                                                        String externalId, String displayName) {
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
                LOG.debugf("resolveScimGroupId: externalId=%s returned %d results (ambiguous), "
                        + "falling back to displayName", externalId, r.totalResults());
            }
        }

        if (id.isEmpty() && displayName != null && !displayName.isBlank()) {
            id = client.findGroupIdByDisplayName(displayName);
        }

        return id;
    }

    /**
     * Resolve the SCIM user id for a Keycloak user.
     *
     * Governed by CFG_LOOKUP_STRATEGY:
     *   "externalId first" (default): try externalId; if empty or ambiguous (totalResults != 1),
     *     fall back to userName.
     *   "name only": skip the externalId HTTP call; go straight to userName.
     */
    private static Optional<String> resolveScimUserId(ScimClient client, ComponentModel target,
                                                       String externalId, String scimUserName) {
        String strategy = ScimTargetProviderFactory.get(target,
                ScimTargetProviderFactory.CFG_LOOKUP_STRATEGY,
                ScimTargetProviderFactory.LOOKUP_STRATEGY_EXTERNAL_ID_FIRST);

        Optional<String> id = Optional.empty();

        if (!ScimTargetProviderFactory.LOOKUP_STRATEGY_NAME_ONLY.equals(strategy)
                && externalId != null && !externalId.isBlank()) {
            id = client.findUserIdByExternalId(externalId);
        }

        if (id.isEmpty() && scimUserName != null && !scimUserName.isBlank()) {
            id = client.findUserIdByUserName(scimUserName);
        }

        return id;
    }

    private static String computeScimUserName(ComponentModel t, UserModel user) {
        String strategy = ScimTargetProviderFactory.get(
                t, ScimTargetProviderFactory.CFG_UNAME_STRATEGY, "username");
        return switch (strategy) {
            case "email"     -> nvl(user.getEmail());
            case "attribute" -> {
                String attr = ScimTargetProviderFactory.get(t, ScimTargetProviderFactory.CFG_UNAME_ATTR, null);
                yield attr == null ? null : nvl(user.getFirstAttribute(attr));
            }
            default          -> user.getUsername();
        };
    }

    private static String nvl(String s) {
        return (s == null || s.isBlank()) ? null : s;
    }

    /**
     * Recomputes and writes GroupMembershipState and pending attributes for the given target
     * based on the updated state values list.
     */
    private static void writeGroupState(GroupModel group, String componentId,
                                        List<String> updatedValues) {
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
        LOG.debugf("writeGroupState group=%s componentId=%s pending=%s",
                group.getName(), componentId, allPending);
    }

    /**
     * Removes all GroupMembershipState and pending attribute entries for the given target.
     * Called ONLY from deprovisionOutOfScopeGroups after a confirmed remote DELETE.
     * Must NOT be called from any sync path.
     */
    private static void clearGroupState(GroupModel group, String componentId) {
        List<String> currentState = group.getAttributeStream(
                GroupMembershipState.ATTRIBUTE_NAME).toList();
        List<String> updatedState = GroupMembershipState.removeAllForComponent(currentState, componentId);

        List<String> allPending = new ArrayList<>(
                group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME).toList());
        allPending.remove(GroupMembershipState.pendingValue(componentId));

        group.setAttribute(GroupMembershipState.ATTRIBUTE_NAME, updatedState);
        group.setAttribute(GroupMembershipState.PENDING_ATTRIBUTE_NAME, allPending);
        LOG.debugf("clearGroupState group=%s componentId=%s", group.getName(), componentId);
    }
}
