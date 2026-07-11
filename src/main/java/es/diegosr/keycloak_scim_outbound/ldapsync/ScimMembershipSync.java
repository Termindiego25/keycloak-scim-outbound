package es.diegosr.keycloak_scim_outbound.ldapsync;

import es.diegosr.keycloak_scim_outbound.http.ScimClient;
import es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory;
import es.diegosr.keycloak_scim_outbound.util.ScimMapper;
import org.keycloak.component.ComponentModel;
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
 * Consumes the state written by LdapSyncNotifierMapper (the
 * "ldapSyncNotifier.filterGroupMembership" attribute) and pushes pending
 * membership changes to the relevant SCIM target(s).
 *
 * Invoked from ScimTargetProviderFactory#sync / #syncSince (ImportSynchronization),
 * triggered when an admin clicks "Synchronize all users" / "Synchronize changed users"
 * on a specific SCIM outbound federation provider in the console -- scoped to just
 * that one componentId.
 *
 * Two modes:
 *   processPendingMembershipChanges -- delta flush; only users with pending entries
 *   processFullUserSync             -- full re-provision all CFG_FILTER_GROUP members
 *
 * PERFORMANCE: processPendingMembershipChanges uses the lightweight indexed attribute
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
     * Delta flush: process only pending entries for the given SCIM target.
     *
     * @param componentIdFilter if non-null, only process pending entries for this SCIM
     *                          target's componentId (used by the manual "Synchronize" trigger).
     *                          If null, process pending entries for every SCIM target in the realm.
     */
    public static void processPendingMembershipChanges(KeycloakSession session, RealmModel realm,
                                                       String componentIdFilter) {
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
            // scanning every user in the realm.
            //
            // Queried against local storage only (not the aggregated session.users()),
            // since PENDING_ATTRIBUTE_NAME is a local bookkeeping attribute, not an LDAP
            // schema attribute. Searching it via the aggregated view causes the LDAP
            // federation provider to push the attribute into a raw LDAP filter sent to
            // AD, which AD rejects with InvalidSearchFilterException. See
            // LdapSyncNotifierMapper for the same pattern.
            Map<String, UserModel> candidates = new LinkedHashMap<>();
            UserStoragePrivateUtil.userLocalStorage(session)
                    .searchForUserByUserAttributeStream(realm,
                            MembershipState.PENDING_ATTRIBUTE_NAME,
                            MembershipState.pendingValue(target.getId()))
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
                    debug("Pending entry found: user=%s target=%s groupId=%s state=%s",
                            user.getUsername(), target.getName(), entry.groupId(), entry.state());

                    String scimUserName = computeScimUserName(target, user);
                    if (scimUserName == null || scimUserName.isBlank()) {
                        err("Could not resolve SCIM userName for user=%s target=%s. Skipping.",
                                user.getUsername(), target.getName());
                        failures++;
                        continue;
                    }

                    try {
                        if (entry.state() == MembershipState.State.NEW_ADDED) {
                            debug("Calling upsertUser: user=%s scimUserName=%s target=%s groupId=%s",
                                    user.getUsername(), scimUserName, target.getName(), entry.groupId());
                            boolean ok = upsertUser(target, client, user, scimUserName);
                            if (ok) {
                                updatedValues.remove(rawValue);
                                MembershipState sent = new MembershipState(
                                        entry.componentId(), entry.groupId(), MembershipState.State.SENT);
                                updatedValues.add(sent.toValue());
                                userChanged = true;
                                pushedAdds++;
                                info("PUSHED ADD user=%s target=%s groupId=%s -> SENT",
                                        user.getUsername(), target.getName(), entry.groupId());
                            } else {
                                failures++;
                                err("FAILED ADD push for user=%s target=%s groupId=%s. Will retry next run.",
                                        user.getUsername(), target.getName(), entry.groupId());
                            }
                        } else if (entry.state() == MembershipState.State.NEW_DELETED) {
                            debug("Calling deprovisionUser: user=%s scimUserName=%s target=%s groupId=%s",
                                    user.getUsername(), scimUserName, target.getName(), entry.groupId());
                            boolean ok = deprovisionUser(target, client, user.getId(), scimUserName);
                            if (ok) {
                                updatedValues.remove(rawValue);
                                userChanged = true;
                                pushedRemoves++;
                                info("PUSHED REMOVE user=%s target=%s groupId=%s -> entry removed",
                                        user.getUsername(), target.getName(), entry.groupId());
                            } else {
                                failures++;
                                err("FAILED REMOVE push for user=%s target=%s groupId=%s. Will retry next run.",
                                        user.getUsername(), target.getName(), entry.groupId());
                            }
                        }
                    } catch (Exception e) {
                        failures++;
                        err("EXCEPTION processing user=%s target=%s groupId=%s state=%s: %s",
                                user.getUsername(), target.getName(), entry.groupId(), entry.state(), e.getMessage());
                    }
                }

                if (hadPendingForThisUser) usersWithPending++;

                if (userChanged) {
                    // Write through local storage: the user object here comes from
                    // session.users() and may be a federated (e.g. read-only LDAP) view.
                    // Writing directly to it throws ReadOnlyException when the LDAP
                    // provider's edit mode is READ_ONLY. See LdapSyncNotifierMapper for
                    // the same pattern.
                    UserModel localUser = UserStoragePrivateUtil.userLocalStorage(session)
                            .getUserById(realm, user.getId());
                    if (localUser != null) {
                        localUser.setAttribute(MembershipState.ATTRIBUTE_NAME, updatedValues);
                        debug("Updated attribute for user=%s -> %s (via local storage)",
                                user.getUsername(), updatedValues);
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
                        .anyMatch(s -> s.componentId().equals(target.getId())
                                && s.state() != MembershipState.State.SENT);
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
    }

    /**
     * Full user sync: re-provision all current members of CFG_FILTER_GROUP and
     * deprovision any users who were previously SENT but are no longer in scope.
     * After processing, clears ALL MembershipState + pending entries for this target
     * on every affected user.
     *
     * Called by sync() (Synchronize all) and by syncSince() when CFG_LDAP_USER_PROV_MODE=Full.
     *
     * @param componentIdFilter if non-null, scope to that target only.
     */
    public static void processFullUserSync(KeycloakSession session, RealmModel realm,
                                           String componentIdFilter) {
        long start = System.currentTimeMillis();
        debug("=== processFullUserSync START realm=%s componentIdFilter=%s ===",
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

        int usersUpserted = 0;
        int usersDeprovisioned = 0;
        int failures = 0;

        for (ComponentModel target : targets) {
            String base  = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_BASE_URL, null);
            String token = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_TOKEN, null);
            if (base == null || token == null) {
                err("Target=%s incomplete configuration (baseUrl/token). Skipping full user sync.", target.getName());
                continue;
            }

            String filterGroupName = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
            if (filterGroupName == null || filterGroupName.isBlank()) {
                debug("Target=%s has no CFG_FILTER_GROUP. Skipping full user sync.", target.getName());
                continue;
            }

            // Resolve the filter group
            Optional<org.keycloak.models.GroupModel> filterGroupOpt = session.groups()
                    .searchForGroupByNameStream(realm, filterGroupName, true, null, null)
                    .findFirst();
            if (filterGroupOpt.isEmpty()) {
                err("Target=%s: filter group '%s' not found in realm=%s. Skipping full user sync.",
                        target.getName(), filterGroupName, realm.getName());
                continue;
            }
            org.keycloak.models.GroupModel filterGroup = filterGroupOpt.get();

            ScimClient client = new ScimClient(base, token);

            // Collect current group members
            Map<String, UserModel> currentMembers = new LinkedHashMap<>();
            session.users().getGroupMembersStream(realm, filterGroup)
                    .forEach(u -> currentMembers.put(u.getId(), u));

            debug("Target=%s: filter group '%s' has %d current member(s). Upserting all.",
                    target.getName(), filterGroupName, currentMembers.size());

            // Upsert every current member
            for (UserModel user : currentMembers.values()) {
                String scimUserName = computeScimUserName(target, user);
                if (scimUserName == null || scimUserName.isBlank()) {
                    err("Could not resolve SCIM userName for user=%s target=%s. Skipping.", user.getUsername(), target.getName());
                    failures++;
                    continue;
                }
                try {
                    debug("Calling upsertUser (full): user=%s scimUserName=%s target=%s",
                            user.getUsername(), scimUserName, target.getName());
                    boolean ok = upsertUser(target, client, user, scimUserName);
                    if (ok) {
                        usersUpserted++;
                        info("FULL UPSERT user=%s target=%s -> OK", user.getUsername(), target.getName());
                    } else {
                        failures++;
                        err("FULL UPSERT FAILED user=%s target=%s.", user.getUsername(), target.getName());
                    }
                } catch (Exception e) {
                    failures++;
                    err("FULL UPSERT EXCEPTION user=%s target=%s: %s", user.getUsername(), target.getName(), e.getMessage());
                }
            }

            // Find users previously SENT (in MembershipState) but no longer in the filter group
            // -- they need to be deprovisioned.
            // Searched against local storage only for the same reason as in processPendingMembershipChanges.
            String sentValue = new MembershipState(target.getId(), filterGroup.getId(), MembershipState.State.SENT).toValue();
            List<UserModel> previouslyProvisioned = UserStoragePrivateUtil.userLocalStorage(session)
                    .searchForUserByUserAttributeStream(realm, MembershipState.ATTRIBUTE_NAME, sentValue)
                    .filter(u -> !currentMembers.containsKey(u.getId()))
                    .collect(Collectors.toList());

            debug("Target=%s: %d previously-SENT user(s) no longer in filter group -- deprovisioning.",
                    target.getName(), previouslyProvisioned.size());

            for (UserModel user : previouslyProvisioned) {
                String scimUserName = computeScimUserName(target, user);
                try {
                    debug("Calling deprovisionUser (full): user=%s scimUserName=%s target=%s",
                            user.getUsername(), scimUserName, target.getName());
                    boolean ok = deprovisionUser(target, client, user.getId(), scimUserName);
                    if (ok) {
                        usersDeprovisioned++;
                        info("FULL DEPROVISION user=%s target=%s -> OK", user.getUsername(), target.getName());
                    } else {
                        failures++;
                        err("FULL DEPROVISION FAILED user=%s target=%s.", user.getUsername(), target.getName());
                    }
                } catch (Exception e) {
                    failures++;
                    err("FULL DEPROVISION EXCEPTION user=%s target=%s: %s", user.getUsername(), target.getName(), e.getMessage());
                }
            }

            // Clear ALL MembershipState + pending entries for this target on all affected users
            // (both current members and deprovisioned ones).
            List<UserModel> allAffected = new ArrayList<>(currentMembers.values());
            for (UserModel u : previouslyProvisioned) {
                if (!currentMembers.containsKey(u.getId())) allAffected.add(u);
            }
            for (UserModel user : allAffected) {
                clearAllStateForTarget(session, realm, user, target.getId());
            }
        }

        long durationMs = System.currentTimeMillis() - start;
        info("=== processFullUserSync DONE realm=%s componentIdFilter=%s: "
                        + "usersUpserted=%d usersDeprovisioned=%d failures=%d durationMs=%d ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter,
                usersUpserted, usersDeprovisioned, failures, durationMs);
    }

    /**
     * Removes the "<componentId>:1" entry from MembershipState.PENDING_ATTRIBUTE_NAME
     * for the given user, if present. Written through local storage for the same
     * read-only-federation reason as the main tracking attribute.
     */
    private static void clearPendingFlag(KeycloakSession session, RealmModel realm,
                                         UserModel user, String componentId) {
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
        debug("Cleared pending flag for user=%s componentId=%s -> %s",
                user.getUsername(), componentId, updatedPending);
    }

    /**
     * Clears ALL MembershipState and pending attribute entries for the given target on
     * the given user. Used after a successful full sync so stale delta entries do not
     * cause incorrect re-processing on the next cycle.
     * Written through local storage.
     */
    private static void clearAllStateForTarget(KeycloakSession session, RealmModel realm,
                                               UserModel user, String componentId) {
        UserModel localUser = UserStoragePrivateUtil.userLocalStorage(session).getUserById(realm, user.getId());
        if (localUser == null) {
            err("Could not resolve local storage user for id=%s; full-state clear skipped for componentId=%s.",
                    user.getId(), componentId);
            return;
        }

        List<String> currentState = user.getAttributeStream(MembershipState.ATTRIBUTE_NAME).toList();
        List<String> updatedState = currentState.stream()
                .filter(raw -> {
                    Optional<MembershipState> parsed = MembershipState.parse(raw);
                    return parsed.isEmpty() || !parsed.get().componentId().equals(componentId);
                })
                .collect(Collectors.toList());
        localUser.setAttribute(MembershipState.ATTRIBUTE_NAME, updatedState);

        List<String> currentPending = user.getAttributeStream(MembershipState.PENDING_ATTRIBUTE_NAME).toList();
        List<String> updatedPending = new ArrayList<>(currentPending);
        updatedPending.remove(MembershipState.pendingValue(componentId));
        localUser.setAttribute(MembershipState.PENDING_ATTRIBUTE_NAME, updatedPending);

        debug("Cleared all state for user=%s componentId=%s", user.getUsername(), componentId);
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

    /**
     * Resolve or create the SCIM user, then patch it with the current KC state.
     * Reads CFG_LOOKUP_STRATEGY from target to decide whether to attempt an
     * externalId lookup before falling back to userName.
     */
    static boolean upsertUser(ComponentModel target, ScimClient scim, UserModel user, String scimUserName) {
        final String externalId = user.getId();
        Optional<String> existingId = resolveScimId(target, scim, externalId, scimUserName);
        if (existingId.isEmpty()) {
            boolean created = scim.createUser(ScimMapper.buildCreateUser(user, scimUserName));
            if (created) return true;
            existingId = resolveScimId(target, scim, externalId, scimUserName);
            return existingId.map(id -> scim.patchUser(id, ScimMapper.buildPatchUser(user, externalId))).orElse(false);
        } else {
            return scim.patchUser(existingId.get(), ScimMapper.buildPatchUser(user, externalId));
        }
    }

    private static boolean deprovisionUser(ComponentModel target, ScimClient scim,
                                           String externalId, String scimUserName) {
        Optional<String> id = resolveScimId(target, scim, externalId, scimUserName);
        if (id.isEmpty()) {
            debug("Deprovision NO-OP: user not found in SCIM (externalId=%s userName=%s)",
                    externalId, scimUserName);
            return true; // nothing to remove counts as a successful removal
        }
        String mode = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_DEPROVISION, "deactivate");
        if ("delete".equals(mode)) {
            return scim.deleteUser(id.get());
        }
        return scim.patchUser(id.get(), ScimMapper.buildDeactivatePatch());
    }

    /**
     * Resolve the SCIM user id for a Keycloak user.
     *
     * Reads CFG_LOOKUP_STRATEGY from target:
     *   "externalId first" (default): try findUserIdByExternalId first; fall back to
     *     findUserIdByUserName if the result is empty.
     *   "name only": skip the externalId HTTP call entirely; go straight to
     *     findUserIdByUserName. Use when the SCIM server ignores the externalId filter.
     */
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
