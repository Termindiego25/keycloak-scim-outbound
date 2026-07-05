package es.diegosr.keycloak_scim_outbound.ldapsync;

import es.diegosr.keycloak_scim_outbound.http.ScimClient;
import es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory;
import es.diegosr.keycloak_scim_outbound.util.ScimMapper;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import es.diegosr.keycloak_scim_outbound.ldapsync.GroupSyncState;
import es.diegosr.keycloak_scim_outbound.util.ScimGroupMapper;

import org.keycloak.models.GroupModel;
import org.keycloak.storage.UserStoragePrivateUtil;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Consumes the state written by LdapSyncNotifierMapper (the
 * "ldapSyncNotifier.filterGroupMembership" attribute) and pushes pending
 * membership changes to the relevant SCIM target(s).
 *
 * Invoked from two places:
 *   1. A 5-minute TimerProvider task (ScimEventListenerProviderFactory#postInit),
 *      scanning ALL SCIM targets in ALL realms.
 *   2. ScimTargetProviderFactory#sync / #syncSince (ImportSynchronization), triggered when
 *      an admin clicks "Synchronize all users" / "Synchronize changed users" on a
 *      specific SCIM outbound federation provider in the console -- scoped to just
 *      that one componentId.
 *
 * PERFORMANCE: this used to do a full user-stream scan per tick
 * (session.users().searchForUserStream(realm, Map.of())) to find users with a pending
 * entry in MembershipState.ATTRIBUTE_NAME -- an O(total realm users) operation on every
 * single sync cycle regardless of how many memberships actually changed (e.g. 941 users
 * scanned every run). It now uses the lightweight indexed attribute
 * MembershipState.PENDING_ATTRIBUTE_NAME (values "<componentId>:1", maintained by
 * LdapSyncNotifierMapper) and looks candidates up per-target via
 * searchForUserByUserAttributeStream(realm, PENDING_ATTRIBUTE_NAME, "<componentId>:1"),
 * which is an indexed local-storage lookup, not a full scan. Only users actually
 * flagged pending for a given target are loaded and processed.
 *
 * NOTE: the lookup above is always run against UserStoragePrivateUtil.userLocalStorage(session),
 * never the aggregated session.users(). PENDING_ATTRIBUTE_NAME is a local bookkeeping
 * attribute with no meaning to any federated provider; searching it through the
 * aggregated view causes federated providers (e.g. the LDAP provider) to push the
 * attribute into their own native query, which fails for attributes they don't recognize.
 */
public final class ScimMembershipSync {

    private static final String LOG_TAG = "[keycloak-scim-outbound/LDAP-SYNC]";

    private ScimMembershipSync() { }

    /**
     * @param componentIdFilter if non-null, only process pending entries for this SCIM
     *                          target's componentId (used by the manual "Synchronize" trigger).
     *                          If null, process pending entries for every SCIM target in the realm
     *                          (used by the periodic timer).
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
            // scanning every user in the realm. Replaces the old
            // session.users().searchForUserStream(realm, Map.of()) full scan.
            //
            // Queried against local storage only (not the aggregated session.users()),
            // since PENDING_ATTRIBUTE_NAME is a local bookkeeping attribute, not an LDAP
            // schema attribute. Searching it via the aggregated view causes the LDAP
            // federation provider to push the attribute into a raw LDAP filter sent to
            // AD, which AD rejects with InvalidSearchFilterException. See
            // LdapSyncNotifierMapper for the same pattern.
            Map<String, UserModel> candidates = new LinkedHashMap<>();
            UserStoragePrivateUtil.userLocalStorage(session)
                    .searchForUserByUserAttributeStream(realm, MembershipState.PENDING_ATTRIBUTE_NAME, MembershipState.pendingValue(target.getId()))
                    .forEach(u -> candidates.putIfAbsent(u.getId(), u));

            debug("Target=%s (id=%s): %d candidate user(s) flagged pending via indexed lookup (no full realm scan).",
                    target.getName(), target.getId(), candidates.size());

            String base = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_BASE_URL, null);
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
                    // Stale pending flag with no backing entry -- clear it defensively.
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

                    if (!entry.componentId().equals(target.getId())) {
                        continue; // entry belongs to a different SCIM target
                    }
                    if (entry.state() == MembershipState.State.SENT) {
                        continue; // already delivered, nothing to do
                    }

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
                    // Write through local storage: the user object here comes from
                    // session.users() and may be a federated (e.g. read-only LDAP) view.
                    // Writing directly to it throws ReadOnlyException when the LDAP
                    // provider's edit mode is READ_ONLY. See LdapSyncNotifierMapper for
                    // the same pattern.
                    UserModel localUser = UserStoragePrivateUtil.userLocalStorage(session).getUserById(realm, user.getId());
                    if (localUser != null) {
                        localUser.setAttribute(MembershipState.ATTRIBUTE_NAME, updatedValues);
                        debug("Updated attribute for user=%s -> %s (via local storage)", user.getUsername(), updatedValues);
                    } else {
                        err("Could not resolve local storage user for id=%s (username=%s); attribute update skipped.",
                                user.getId(), user.getUsername());
                    }
                }

                // Once this user has no more un-SENT entries for THIS target, clear its
                // pending flag for this target so the next sync's indexed lookup skips it.
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

        // Process any pending SCIM group changes (create/update/delete of /Groups resources)
        processPendingGroupChanges(session, realm, targets);
    }

    /**
     * For each SCIM target that has group provisioning enabled, iterates groups that have
     * a pending sync state (NEEDS_SYNC or NEEDS_DELETE in GroupSyncState) and pushes the
     * corresponding SCIM operation.
     *
     * NEEDS_SYNC  -> upsert /Groups (POST if not found, PATCH members+displayName if found).
     *               Members are resolved by looking up each current Keycloak group member in
     *               the SCIM /Users endpoint (by externalId, fallback by userName).
     *               After a successful push the state is set to SYNCED and the synced name
     *               is recorded in a sibling attribute for rename detection.
     *
     * NEEDS_DELETE -> DELETE /Groups/{id} (or skip if already gone from SCIM).
     *                After a successful push, all state attributes for this target are removed
     *                from the group.
     *
     * Groups are located via GroupSyncState.findPendingGroups(realm), which iterates all
     * realm groups but checks only those with a non-empty "scim.outbound.pending" attribute.
     * Group counts are typically small (hundreds at most), so this scan is cheap.
     */
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
                java.util.Optional<GroupSyncState.State> stateOpt = GroupSyncState.getState(group, target.getId());
                if (stateOpt.isEmpty()) continue; // no state for this target

                GroupSyncState.State state = stateOpt.get();
                if (state == GroupSyncState.State.SYNCED) continue; // nothing to do

                debug("Processing group='%s' state=%s target=%s", group.getName(), state, target.getName());

                try {
                    if (state == GroupSyncState.State.NEEDS_SYNC) {
                        boolean ok = upsertScimGroup(client, group, target, session, realm);
                        if (ok) {
                            // Record the synced name for rename detection on next sync
                            group.setAttribute(GroupSyncState.STATE_ATTR_PREFIX + target.getId() + ".name",
                                    java.util.List.of(group.getName()));
                            GroupSyncState.clearState(group, target.getId());
                            // Re-set as SYNCED (clearState removed the attribute, we need SYNCED)
                            group.setAttribute(GroupSyncState.STATE_ATTR_PREFIX + target.getId(),
                                    java.util.List.of(GroupSyncState.State.SYNCED.name()));
                            // Remove the pending flag (no longer undelivered)
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

    /**
     * Upsert a SCIM /Groups resource:
     *   1. Try to find it by externalId (Keycloak group UUID), then by displayName.
     *   2. If not found: POST /Groups with all current members resolved.
     *   3. If found: PATCH to replace displayName and members list.
     * Returns true if the operation succeeded.
     */
    private static boolean upsertScimGroup(ScimClient client, GroupModel group,
                                           ComponentModel target, KeycloakSession session, RealmModel realm) {
        // Resolve current members of the Keycloak group into SCIM user ids
        List<ScimGroupMapper.ScimMemberRef> members = resolveGroupMembers(client, group, target, session, realm);

        // Look up existing SCIM group
        java.util.Optional<String> scimGroupId = client.findGroupIdByExternalId(group.getId());
        if (scimGroupId.isEmpty()) {
            scimGroupId = client.findGroupIdByDisplayName(group.getName());
        }

        if (scimGroupId.isEmpty()) {
            // Create new SCIM group
            boolean created = client.createGroup(ScimGroupMapper.buildCreateGroup(group, members));
            if (created) return true;
            // 409 conflict: race condition -- re-resolve and patch
            scimGroupId = client.findGroupIdByExternalId(group.getId());
            if (scimGroupId.isEmpty()) scimGroupId = client.findGroupIdByDisplayName(group.getName());
        }

        // Patch existing SCIM group (update displayName + replace members)
        return scimGroupId
                .map(id -> client.patchGroup(id, ScimGroupMapper.buildReplaceGroupPatch(group.getName(), members)))
                .orElse(false);
    }

    /**
     * Delete the SCIM /Groups resource corresponding to the Keycloak group.
     * Returns true if deleted or already absent.
     */
    private static boolean deleteScimGroup(ScimClient client, GroupModel group) {
        java.util.Optional<String> scimGroupId = client.findGroupIdByExternalId(group.getId());
        if (scimGroupId.isEmpty()) scimGroupId = client.findGroupIdByDisplayName(group.getName());
        if (scimGroupId.isEmpty()) {
            debug("Group '%s' not found in SCIM target; treating DELETE as NO-OP (already gone).", group.getName());
            return true;
        }
        return client.deleteGroup(scimGroupId.get());
    }

    /**
     * Resolves the current members of a Keycloak group into SCIM member references by
     * looking up each member user in the SCIM /Users endpoint.
     * Users not yet provisioned (no SCIM id found) are skipped; they will be picked up
     * on the next group sync once the user-side provisioning has completed.
     */
    private static List<ScimGroupMapper.ScimMemberRef> resolveGroupMembers(
            ScimClient client, GroupModel group, ComponentModel target,
            KeycloakSession session, RealmModel realm) {

        List<ScimGroupMapper.ScimMemberRef> refs = new java.util.ArrayList<>();
        session.users().getGroupMembersStream(realm, group).forEach(user -> {
            String scimUserName = computeScimUserName(target, user);
            if (scimUserName == null || scimUserName.isBlank()) return;

            java.util.Optional<String> scimId = resolveScimId(client, user.getId(), scimUserName);
            scimId.ifPresent(id -> refs.add(new ScimGroupMapper.ScimMemberRef(id, scimUserName)));
        });
        return refs;
    }

    private static boolean isGroupProvisioningEnabled(ComponentModel target) {
        return Boolean.parseBoolean(
                ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_PROVISION_GROUPS, "false"));
    }

    /**
     * Removes the "<componentId>:1" entry from MembershipState.PENDING_ATTRIBUTE_NAME
     * for the given user, if present. Written through local storage for the same
     * read-only-federation reason as the main tracking attribute.
     */
    private static void clearPendingFlag(KeycloakSession session, RealmModel realm, UserModel user, String componentId) {
        List<String> currentPending = user.getAttributeStream(MembershipState.PENDING_ATTRIBUTE_NAME).toList();
        String pendingValue = MembershipState.pendingValue(componentId);
        if (!currentPending.contains(pendingValue)) {
            return; // nothing to clear
        }

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

    /* ===== SCIM push helpers (mirrors ScimEventListenerProvider logic) ===== */

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

    private static boolean deprovisionUser(ComponentModel t, ScimClient scim, String externalId, String scimUserName) {
        Optional<String> id = resolveScimId(scim, externalId, scimUserName);
        if (id.isEmpty()) {
            debug("Deprovision NO-OP: user not found in SCIM target=%s (externalId=%s userName=%s)",
                    t.getName(), externalId, scimUserName);
            return true; // nothing to remove counts as a successful removal
        }
        String mode = ScimTargetProviderFactory.get(t, ScimTargetProviderFactory.CFG_DEPROVISION, "deactivate");
        if ("delete".equals(mode)) {
            return scim.deleteUser(id.get());
        }
        return scim.patchUser(id.get(), ScimMapper.buildDeactivatePatch());
    }

    private static Optional<String> resolveScimId(ScimClient scim, String externalId, String scimUserName) {
        Optional<String> id = (externalId != null && !externalId.isBlank())
                ? scim.findUserIdByExternalId(externalId)
                : Optional.empty();
        if (id.isEmpty() && scimUserName != null && !scimUserName.isBlank()) {
            id = scim.findUserIdByUserName(scimUserName);
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
