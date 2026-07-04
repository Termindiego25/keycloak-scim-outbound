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
 * Full user-stream scan per tick (no indexed attribute search) -- acceptable for
 * small/medium realms. See README for the indexed-search upgrade path if this
 * realm's user count grows large enough to make that matter.
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

        java.util.Map<String, ComponentModel> targetsById = new java.util.HashMap<>();
        for (ComponentModel t : targets) targetsById.put(t.getId(), t);

        int usersScanned = 0;
        int usersWithPending = 0;
        int pushedAdds = 0;
        int pushedRemoves = 0;
        int failures = 0;

        // NOTE: UserProvider#getUsersStream(RealmModel) was removed in this Keycloak version.
        // Use searchForUserStream(RealmModel, Map) with an empty params map to fetch all users instead.
        List<UserModel> allUsers = session.users().searchForUserStream(realm, Map.of()).toList();
        debug("Scanning %d user(s) in realm=%s for pending entries...", allUsers.size(), realm.getName());

        for (UserModel user : allUsers) {
            usersScanned++;
            List<String> values = user.getAttributeStream(MembershipState.ATTRIBUTE_NAME).toList();
            if (values.isEmpty()) continue;

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

                ComponentModel target = targetsById.get(entry.componentId());
                if (target == null) {
                    // Not in scope for this run (filtered out, or stale/deleted target) -- skip silently.
                    continue;
                }

                if (entry.state() == MembershipState.State.SENT) {
                    continue; // already delivered, nothing to do
                }

                hadPendingForThisUser = true;
                debug("Pending entry found: user=%s target=%s group='%s' state=%s",
                        user.getUsername(), target.getName(), entry.groupName(), entry.state());

                String base = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_BASE_URL, null);
                String token = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_TOKEN, null);
                if (base == null || token == null) {
                    err("Target=%s incomplete configuration (baseUrl/token). Skipping pending entry for user=%s.",
                            target.getName(), user.getUsername());
                    failures++;
                    continue;
                }

                String scimUserName = computeScimUserName(target, user);
                if (scimUserName == null || scimUserName.isBlank()) {
                    err("Could not resolve SCIM userName for user=%s target=%s. Skipping.",
                            user.getUsername(), target.getName());
                    failures++;
                    continue;
                }

                ScimClient client = new ScimClient(base, token);

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
        }

        long durationMs = System.currentTimeMillis() - start;
        info("=== processPendingMembershipChanges DONE realm=%s componentIdFilter=%s: "
                        + "usersScanned=%d usersWithPending=%d pushedAdds=%d pushedRemoves=%d failures=%d durationMs=%d ===",
                realm.getName(), componentIdFilter == null ? "<all>" : componentIdFilter,
                usersScanned, usersWithPending, pushedAdds, pushedRemoves, failures, durationMs);
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
