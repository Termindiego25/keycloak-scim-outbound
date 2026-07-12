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
import org.keycloak.storage.UserStoragePrivateUtil;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Consumes the state written by LdapSyncNotifierMapper
 * ("ldapSyncNotifier.filterGroupMembership" attribute) and pushes pending
 * membership changes to the relevant SCIM target(s).
 *
 * Two modes:
 *   processPendingMembershipChanges -- delta flush; only users with pending entries
 *   processFullUserSync             -- full re-provision all CFG_FILTER_GROUP members
 *
 * STATE INVARIANT (issues 2 and 4):
 * MembershipState attributes are permanent lifecycle markers. They must never be
 * bulk-cleared by a sync run. clearAllStateForTarget has been removed.
 *
 * processFullUserSync transitions state after each operation:
 *   - Successful upsert  -> entry becomes SENT (or is written as SENT if absent).
 *   - Successful deprov  -> entry is removed entirely (user is gone; nothing to track).
 *   - Failed operation   -> entry is left untouched for retry on the next cycle.
 *
 * The pending flag (ldapSyncNotifier.pending) is cleared only when no non-SENT entries
 * remain for the target on that user.
 *
 * PERFORMANCE: processPendingMembershipChanges uses the lightweight indexed attribute
 * MembershipState.PENDING_ATTRIBUTE_NAME and looks up candidates per-target via
 * searchForUserByUserAttributeStream, which is an indexed local-storage lookup.
 *
 * NOTE: all user-attribute searches and writes go through UserStoragePrivateUtil.userLocalStorage
 * because PENDING_ATTRIBUTE_NAME / ATTRIBUTE_NAME are local bookkeeping attributes unknown to
 * federated providers (e.g. LDAP). Searching them through the aggregated session.users() causes
 * federated providers to push the attribute into their own native query, which fails.
 */
public final class ScimMembershipSync {

    private static final Logger LOG = Logger.getLogger(ScimMembershipSync.class);

    private ScimMembershipSync() {}

    // =========================================================================
    // Delta flush
    // =========================================================================

    /**
     * Delta flush: process only pending entries for the given SCIM target.
     *
     * @param componentIdFilter if non-null, only process entries for this target's componentId.
     *                          If null, process entries for every SCIM target in the realm.
     */
    public static void processPendingMembershipChanges(KeycloakSession session, RealmModel realm,
                                                       String componentIdFilter) {
        long start = System.currentTimeMillis();
        LOG.infof("=== processPendingMembershipChanges START realm=%s componentIdFilter=%s ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter);

        List<ComponentModel> targets = realm.getComponentsStream()
                .filter(c -> ScimTargetProviderFactory.ID.equals(c.getProviderId()))
                .filter(c -> componentIdFilter == null || componentIdFilter.equals(c.getId()))
                .toList();

        if (targets.isEmpty()) {
            LOG.debugf("No matching SCIM targets in realm=%s (filter=%s). Nothing to do.",
                    realm.getName(), componentIdFilter);
            return;
        }

        int usersScanned    = 0;
        int usersWithPending = 0;
        int pushedAdds      = 0;
        int pushedRemoves   = 0;
        int failures        = 0;

        for (ComponentModel target : targets) {
            Map<String, UserModel> candidates = new LinkedHashMap<>();
            UserStoragePrivateUtil.userLocalStorage(session)
                    .searchForUserByUserAttributeStream(realm,
                            MembershipState.PENDING_ATTRIBUTE_NAME,
                            MembershipState.pendingValue(target.getId()))
                    .forEach(u -> candidates.putIfAbsent(u.getId(), u));

            LOG.debugf("Target=%s: %d candidate user(s) pending.", target.getName(), candidates.size());

            String base  = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_BASE_URL, null);
            String token = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_TOKEN, null);
            if (base == null || token == null) {
                LOG.errorf("Target=%s incomplete configuration (baseUrl/token). Skipping.", target.getName());
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
                boolean hadPending  = false;

                for (String rawValue : values) {
                    Optional<MembershipState> parsed = MembershipState.parse(rawValue);
                    if (parsed.isEmpty()) continue;
                    MembershipState entry = parsed.get();
                    if (!entry.componentId().equals(target.getId())) continue;
                    if (entry.state() == MembershipState.State.SENT) continue;

                    hadPending = true;
                    String scimUserName = computeScimUserName(target, user);
                    if (scimUserName == null || scimUserName.isBlank()) {
                        LOG.errorf("Cannot resolve SCIM userName for user=%s target=%s. Skipping.",
                                user.getUsername(), target.getName());
                        failures++;
                        continue;
                    }

                    try {
                        if (entry.state() == MembershipState.State.NEW_ADDED) {
                            boolean ok = upsertUser(target, client, user, scimUserName);
                            if (ok) {
                                updatedValues.remove(rawValue);
                                updatedValues.add(new MembershipState(
                                        entry.componentId(), entry.groupId(),
                                        MembershipState.State.SENT).toValue());
                                userChanged = true;
                                pushedAdds++;
                                LOG.infof("PUSHED ADD user=%s target=%s groupId=%s -> SENT",
                                        user.getUsername(), target.getName(), entry.groupId());
                            } else {
                                failures++;
                                LOG.errorf("FAILED ADD user=%s target=%s groupId=%s. Will retry.",
                                        user.getUsername(), target.getName(), entry.groupId());
                            }
                        } else if (entry.state() == MembershipState.State.NEW_DELETED) {
                            boolean ok = deprovisionUser(target, client, user.getId(), scimUserName);
                            if (ok) {
                                updatedValues.remove(rawValue);
                                userChanged = true;
                                pushedRemoves++;
                                LOG.infof("PUSHED REMOVE user=%s target=%s groupId=%s -> entry removed",
                                        user.getUsername(), target.getName(), entry.groupId());
                            } else {
                                failures++;
                                LOG.errorf("FAILED REMOVE user=%s target=%s groupId=%s. Will retry.",
                                        user.getUsername(), target.getName(), entry.groupId());
                            }
                        }
                    } catch (Exception e) {
                        failures++;
                        LOG.errorf("EXCEPTION user=%s target=%s groupId=%s state=%s: %s",
                                user.getUsername(), target.getName(), entry.groupId(), entry.state(),
                                e.getMessage());
                    }
                }

                if (hadPending) usersWithPending++;

                if (userChanged) {
                    writeUserState(session, realm, user, updatedValues);
                }

                boolean stillPending = updatedValues.stream()
                        .map(MembershipState::parse)
                        .filter(Optional::isPresent)
                        .map(Optional::get)
                        .anyMatch(s -> s.componentId().equals(target.getId())
                                && s.state() != MembershipState.State.SENT);
                if (!stillPending) {
                    clearPendingFlag(session, realm, user, target.getId());
                }
            }
        }

        LOG.infof("=== processPendingMembershipChanges DONE realm=%s componentIdFilter=%s: "
                        + "usersScanned=%d usersWithPending=%d pushedAdds=%d pushedRemoves=%d "
                        + "failures=%d durationMs=%d ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter,
                usersScanned, usersWithPending, pushedAdds, pushedRemoves, failures,
                System.currentTimeMillis() - start);
    }

    // =========================================================================
    // Full sync
    // =========================================================================

    /**
     * Full user sync: re-provision all current members of CFG_FILTER_GROUP and deprovision
     * any users who were previously SENT but are no longer in scope.
     *
     * STATE INVARIANT: MembershipState attributes survive this call.
     *   - Successful upsert  -> entry transitioned to SENT.
     *   - Successful deprov  -> entry removed entirely.
     *   - Failed operation   -> entry left untouched for retry.
     * clearAllStateForTarget has been removed and is no longer called.
     *
     * @param componentIdFilter if non-null, scope to that target only.
     */
    public static void processFullUserSync(KeycloakSession session, RealmModel realm,
                                           String componentIdFilter) {
        long start = System.currentTimeMillis();
        LOG.infof("=== processFullUserSync START realm=%s componentIdFilter=%s ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter);

        List<ComponentModel> targets = realm.getComponentsStream()
                .filter(c -> ScimTargetProviderFactory.ID.equals(c.getProviderId()))
                .filter(c -> componentIdFilter == null || componentIdFilter.equals(c.getId()))
                .toList();

        if (targets.isEmpty()) {
            LOG.debugf("No matching SCIM targets in realm=%s (filter=%s). Nothing to do.",
                    realm.getName(), componentIdFilter);
            return;
        }

        int usersUpserted     = 0;
        int usersDeprovisioned = 0;
        int failures          = 0;

        for (ComponentModel target : targets) {
            String base  = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_BASE_URL, null);
            String token = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_TOKEN, null);
            if (base == null || token == null) {
                LOG.errorf("Target=%s incomplete config. Skipping full user sync.", target.getName());
                continue;
            }

            String filterGroupName = ScimTargetProviderFactory.get(
                    target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
            if (filterGroupName == null || filterGroupName.isBlank()) {
                LOG.debugf("Target=%s has no CFG_FILTER_GROUP. Skipping full user sync.", target.getName());
                continue;
            }

            Optional<GroupModel> filterGroupOpt = session.groups()
                    .searchForGroupByNameStream(realm, filterGroupName, true, null, null)
                    .findFirst();
            if (filterGroupOpt.isEmpty()) {
                LOG.errorf("Target=%s: filter group '%s' not found in realm=%s. Skipping.",
                        target.getName(), filterGroupName, realm.getName());
                continue;
            }
            GroupModel filterGroup = filterGroupOpt.get();

            ScimClient client = new ScimClient(base, token);

            Map<String, UserModel> currentMembers = new LinkedHashMap<>();
            session.users().getGroupMembersStream(realm, filterGroup)
                    .forEach(u -> currentMembers.put(u.getId(), u));

            LOG.debugf("Target=%s: filter group '%s' has %d current member(s).",
                    target.getName(), filterGroupName, currentMembers.size());

            // Upsert every current member.
            for (UserModel user : currentMembers.values()) {
                String scimUserName = computeScimUserName(target, user);
                if (scimUserName == null || scimUserName.isBlank()) {
                    LOG.errorf("Cannot resolve SCIM userName for user=%s target=%s. Skipping.",
                            user.getUsername(), target.getName());
                    failures++;
                    continue;
                }
                try {
                    boolean ok = upsertUser(target, client, user, scimUserName);
                    if (ok) {
                        usersUpserted++;
                        LOG.infof("FULL UPSERT user=%s target=%s -> OK", user.getUsername(), target.getName());
                        // Transition state to SENT for this (target, filterGroup) pair.
                        transitionUserStateToSent(session, realm, user,
                                target.getId(), filterGroup.getId());
                    } else {
                        failures++;
                        LOG.errorf("FULL UPSERT FAILED user=%s target=%s.", user.getUsername(), target.getName());
                        // Entry left untouched for retry.
                    }
                } catch (Exception e) {
                    failures++;
                    LOG.errorf("FULL UPSERT EXCEPTION user=%s target=%s: %s",
                            user.getUsername(), target.getName(), e.getMessage());
                }
            }

            // Find users previously SENT for this (target, filterGroup) but no longer members.
            // Searched against local storage only (ATTRIBUTE_NAME is a local bookkeeping attr).
            String sentValue = new MembershipState(
                    target.getId(), filterGroup.getId(), MembershipState.State.SENT).toValue();
            List<UserModel> previouslyProvisioned = UserStoragePrivateUtil.userLocalStorage(session)
                    .searchForUserByUserAttributeStream(realm, MembershipState.ATTRIBUTE_NAME, sentValue)
                    .filter(u -> !currentMembers.containsKey(u.getId()))
                    .collect(Collectors.toList());

            LOG.debugf("Target=%s: %d previously-SENT user(s) no longer in filter group.",
                    target.getName(), previouslyProvisioned.size());

            for (UserModel user : previouslyProvisioned) {
                String scimUserName = computeScimUserName(target, user);
                try {
                    boolean ok = deprovisionUser(target, client, user.getId(), scimUserName);
                    if (ok) {
                        usersDeprovisioned++;
                        LOG.infof("FULL DEPROVISION user=%s target=%s -> OK",
                                user.getUsername(), target.getName());
                        // Remove the SENT entry entirely -- user is gone, nothing left to track.
                        removeUserStateEntry(session, realm, user,
                                target.getId(), filterGroup.getId());
                    } else {
                        failures++;
                        LOG.errorf("FULL DEPROVISION FAILED user=%s target=%s.",
                                user.getUsername(), target.getName());
                        // Entry left as SENT for retry.
                    }
                } catch (Exception e) {
                    failures++;
                    LOG.errorf("FULL DEPROVISION EXCEPTION user=%s target=%s: %s",
                            user.getUsername(), target.getName(), e.getMessage());
                }
            }
        }

        LOG.infof("=== processFullUserSync DONE realm=%s componentIdFilter=%s: "
                        + "usersUpserted=%d usersDeprovisioned=%d failures=%d durationMs=%d ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter,
                usersUpserted, usersDeprovisioned, failures,
                System.currentTimeMillis() - start);
    }

    // =========================================================================
    // State helpers
    // =========================================================================

    /**
     * Transitions the MembershipState entry for (componentId, groupId) to SENT.
     * If no entry exists for this pair, a new SENT entry is added.
     * Entries for other targets or other groups are left untouched.
     * The pending flag is cleared if no non-SENT entries remain for this target.
     */
    private static void transitionUserStateToSent(KeycloakSession session, RealmModel realm,
                                                   UserModel user, String componentId, String groupId) {
        List<String> current = new ArrayList<>(
                user.getAttributeStream(MembershipState.ATTRIBUTE_NAME).toList());

        boolean found = false;
        List<String> updated = new ArrayList<>();
        for (String raw : current) {
            Optional<MembershipState> parsed = MembershipState.parse(raw);
            if (parsed.isPresent()
                    && parsed.get().componentId().equals(componentId)
                    && parsed.get().groupId().equals(groupId)) {
                // Replace with SENT regardless of prior state.
                updated.add(new MembershipState(componentId, groupId,
                        MembershipState.State.SENT).toValue());
                found = true;
            } else {
                updated.add(raw);
            }
        }
        if (!found) {
            updated.add(new MembershipState(componentId, groupId,
                    MembershipState.State.SENT).toValue());
        }

        writeUserState(session, realm, user, updated);

        boolean stillPending = updated.stream()
                .map(MembershipState::parse)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .anyMatch(s -> s.componentId().equals(componentId)
                        && s.state() != MembershipState.State.SENT);
        if (!stillPending) {
            clearPendingFlag(session, realm, user, componentId);
        }
    }

    /**
     * Removes the MembershipState entry for (componentId, groupId) entirely.
     * Used after a successful deprovision: user is gone, nothing left to track.
     * Entries for other targets or other groups are left untouched.
     * The pending flag is cleared if no non-SENT entries remain for this target.
     */
    private static void removeUserStateEntry(KeycloakSession session, RealmModel realm,
                                              UserModel user, String componentId, String groupId) {
        List<String> current = new ArrayList<>(
                user.getAttributeStream(MembershipState.ATTRIBUTE_NAME).toList());

        List<String> updated = current.stream()
                .filter(raw -> {
                    Optional<MembershipState> parsed = MembershipState.parse(raw);
                    if (parsed.isEmpty()) return true;
                    return !(parsed.get().componentId().equals(componentId)
                            && parsed.get().groupId().equals(groupId));
                })
                .collect(Collectors.toList());

        writeUserState(session, realm, user, updated);

        boolean stillPending = updated.stream()
                .map(MembershipState::parse)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .anyMatch(s -> s.componentId().equals(componentId)
                        && s.state() != MembershipState.State.SENT);
        if (!stillPending) {
            clearPendingFlag(session, realm, user, componentId);
        }
    }

    /**
     * Writes the updated MembershipState attribute list through local storage.
     * Must go through UserStoragePrivateUtil because the user object from session.users()
     * may be a federated (read-only LDAP) view and direct writes throw ReadOnlyException.
     */
    private static void writeUserState(KeycloakSession session, RealmModel realm,
                                        UserModel user, List<String> updatedValues) {
        UserModel localUser = UserStoragePrivateUtil.userLocalStorage(session)
                .getUserById(realm, user.getId());
        if (localUser == null) {
            LOG.errorf("Cannot resolve local storage user for id=%s (username=%s); state write skipped.",
                    user.getId(), user.getUsername());
            return;
        }
        localUser.setAttribute(MembershipState.ATTRIBUTE_NAME, updatedValues);
        LOG.debugf("writeUserState user=%s -> %s", user.getUsername(), updatedValues);
    }

    /**
     * Removes the pending flag for the given target from the user's PENDING_ATTRIBUTE_NAME.
     * Written through local storage for the same reason as writeUserState.
     */
    private static void clearPendingFlag(KeycloakSession session, RealmModel realm,
                                          UserModel user, String componentId) {
        List<String> current = user.getAttributeStream(MembershipState.PENDING_ATTRIBUTE_NAME).toList();
        String pendingValue = MembershipState.pendingValue(componentId);
        if (!current.contains(pendingValue)) return;

        List<String> updated = new ArrayList<>(current);
        updated.remove(pendingValue);

        UserModel localUser = UserStoragePrivateUtil.userLocalStorage(session)
                .getUserById(realm, user.getId());
        if (localUser == null) {
            LOG.errorf("Cannot resolve local storage user for id=%s; pending-flag clear skipped for componentId=%s.",
                    user.getId(), componentId);
            return;
        }
        localUser.setAttribute(MembershipState.PENDING_ATTRIBUTE_NAME, updated);
        LOG.debugf("clearPendingFlag user=%s componentId=%s", user.getUsername(), componentId);
    }

    // =========================================================================
    // SCIM push helpers
    // =========================================================================

    static boolean upsertUser(ComponentModel target, ScimClient scim,
                               UserModel user, String scimUserName) {
        final String externalId = user.getId();
        Optional<String> existingId = resolveScimId(target, scim, externalId, scimUserName);
        if (existingId.isEmpty()) {
            boolean created = scim.createUser(ScimMapper.buildCreateUser(user, scimUserName));
            if (created) return true;
            existingId = resolveScimId(target, scim, externalId, scimUserName);
            return existingId.map(id -> scim.patchUser(id, ScimMapper.buildPatchUser(user, externalId)))
                             .orElse(false);
        }
        return scim.patchUser(existingId.get(), ScimMapper.buildPatchUser(user, externalId));
    }

    private static boolean deprovisionUser(ComponentModel target, ScimClient scim,
                                            String externalId, String scimUserName) {
        Optional<String> id = resolveScimId(target, scim, externalId, scimUserName);
        if (id.isEmpty()) {
            LOG.debugf("Deprovision NO-OP: user not found (externalId=%s userName=%s)",
                    externalId, scimUserName);
            return true; // already absent -- counts as success
        }
        String mode = ScimTargetProviderFactory.get(
                target, ScimTargetProviderFactory.CFG_DEPROVISION, "deactivate");
        if ("delete".equals(mode)) return scim.deleteUser(id.get());
        return scim.patchUser(id.get(), ScimMapper.buildDeactivatePatch());
    }

    private static Optional<String> resolveScimId(ComponentModel target, ScimClient scim,
                                                    String externalId, String scimUserName) {
        String strategy = ScimTargetProviderFactory.get(target,
                ScimTargetProviderFactory.CFG_LOOKUP_STRATEGY,
                ScimTargetProviderFactory.LOOKUP_STRATEGY_EXTERNAL_ID_FIRST);

        Optional<String> id = Optional.empty();

        if (!ScimTargetProviderFactory.LOOKUP_STRATEGY_NAME_ONLY.equals(strategy)
                && externalId != null && !externalId.isBlank()) {
            id = scim.findUserIdByExternalId(externalId);
        }

        if (id.isEmpty() && scimUserName != null && !scimUserName.isBlank()) {
            id = scim.findUserIdByUserName(scimUserName);
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
}
