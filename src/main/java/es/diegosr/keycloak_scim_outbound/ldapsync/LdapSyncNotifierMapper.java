package es.diegosr.keycloak_scim_outbound.ldapsync;

import es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.UserStoragePrivateUtil;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.mappers.LDAPStorageMapper;
import org.keycloak.storage.user.SynchronizationResult;

import javax.naming.AuthenticationException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * LDAP Storage Mapper that has NO knowledge of SCIM push logic. Its only job is to
 * record, per SCIM outbound target (identified by ComponentModel id), whether the user
 * is currently a member of that target's configured CFG_FILTER_GROUP, and flag a
 * pending state change ("NEW_ADDED" / "NEW_DELETED") whenever that membership differs
 * from what was last recorded.
 *
 * Also records group-level SCIM membership state (GroupMembershipState) for each in-scope
 * group per target when CFG_SYNC_GROUPS is enabled, enabling the LDAP-driven /Groups
 * provisioning path (ScimGroupSync).
 *
 * There are TWO entry points that can trigger this check, because Keycloak's LDAP
 * federation layer does not consistently notify per-user mappers of group membership
 * changes -- it depends on the built-in group-ldap-mapper's configured Mode:
 *
 * - onImportUserFromLDAP(...): fires per user during "Synchronize all/changed users"
 *   ONLY when the group-ldap-mapper is running in IMPORT mode (membership gets
 *   written into Keycloak's local user/group tables during per-user import).
 *
 * - syncDataFromFederationProviderToKeycloak(...): fires once per full LDAP sync run
 *   (including "changed users" delta syncs -- Keycloak calls every registered
 *   LDAPStorageMapper's syncDataFromFederationProviderToKeycloak on EVERY sync,
 *   regardless of delta/full). This is the ONLY reliable hook when group-ldap-mapper
 *   is in LDAP_ONLY (or READ_ONLY) mode, because in that mode membership is computed
 *   live from LDAP via user.getGroupsStream() and never routed through the per-user
 *   import callback.
 *
 * IMPORTANT (perf): this hook must NOT iterate every user in the realm on every
 * sync -- with hundreds/thousands of users that makes every LDAP sync (including
 * frequent delta syncs) extremely slow. Instead we build a small, targeted
 * candidate set (see buildCandidateUsers below) using indexed/scoped lookups.
 *
 * IMPORTANT: this mapper must be ordered AFTER the built-in "group-ldap-mapper" in the
 * LDAP provider's Mappers list, so that user.getGroupsStream() already reflects the
 * group membership computed during this same sync pass. See README for setup.
 *
 * The actual SCIM push happens elsewhere (ScimMembershipSync / ScimGroupSync), triggered
 * by the SCIM target's own "Synchronize" action -- this class never calls out to SCIM.
 *
 * WRITE SAFETY: when the LDAP provider's edit mode is READ_ONLY (or the built-in
 * group-ldap-mapper mode causes Keycloak to wrap the user in a
 * ReadonlyLDAPUserModelDelegate during sync), calling setAttribute(...) directly on the
 * UserModel passed in by the LDAP sync machinery throws
 * org.keycloak.storage.ReadOnlyException: "Federated storage is not writable". Our
 * tracking attributes (MembershipState.ATTRIBUTE_NAME and
 * MembershipState.PENDING_ATTRIBUTE_NAME) are purely local bookkeeping values that have
 * nothing to do with LDAP, so we must bypass that read-only delegate and write them
 * directly on Keycloak's LOCAL user storage instead, via
 * UserStoragePrivateUtil.userLocalStorage(session).
 *
 * Group attributes (GroupMembershipState.*) are written directly on GroupModel --
 * groups are realm-local, not federated storage, so no UserStoragePrivateUtil is needed.
 */
public class LdapSyncNotifierMapper implements LDAPStorageMapper {

    private static final String LOG_TAG = "[keycloak-scim-outbound/LDAP-SYNC-MAPPER]";

    private final KeycloakSession session;
    private final ComponentModel model;

    public LdapSyncNotifierMapper(KeycloakSession session, ComponentModel model) {
        this.session = session;
        this.model = model;
    }

    @Override
    public void onImportUserFromLDAP(LDAPObject ldapUser, UserModel user, RealmModel realm, boolean isCreate) {
        debug("onImportUserFromLDAP fired: user=%s isCreate=%s realm=%s", user.getUsername(), isCreate, realm.getName());
        checkAndUpdateMembership(realm, user);
    }

    /**
     * Re-checks group membership for a single user against all configured SCIM targets
     * and updates the tracking attributes if anything changed. Shared by both
     * onImportUserFromLDAP (IMPORT mode) and the targeted sweep below (LDAP_ONLY mode).
     */
    private void checkAndUpdateMembership(RealmModel realm, UserModel user) {
        List<ComponentModel> scimTargets = realm.getComponentsStream()
                .filter(c -> ScimTargetProviderFactory.ID.equals(c.getProviderId()))
                .toList();

        if (scimTargets.isEmpty()) {
            debug("No SCIM outbound targets configured in realm=%s. Nothing to do for user=%s.",
                    realm.getName(), user.getUsername());
            return;
        }

        List<String> currentValues = new ArrayList<>(
                user.getAttributeStream(MembershipState.ATTRIBUTE_NAME).toList());
        boolean changed = false;

        for (ComponentModel target : scimTargets) {
            String groupName = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
            if (groupName == null || groupName.isBlank()) {
                debug("Target=%s has no CFG_FILTER_GROUP configured. Skipping for user=%s.",
                        target.getName(), user.getUsername());
                continue;
            }

            // Resolve the filter group to get its stable ID for serialization.
            Optional<GroupModel> filterGroup = session.groups()
                    .searchForGroupByNameStream(realm, groupName, true, null, null)
                    .findFirst();
            if (filterGroup.isEmpty()) {
                debug("Filter group '%s' not found in realm=%s. Skipping target=%s for user=%s.",
                        groupName, realm.getName(), target.getName(), user.getUsername());
                continue;
            }
            String groupId = filterGroup.get().getId();

            boolean isMemberNow = user.getGroupsStream().anyMatch(g -> groupId.equals(g.getId()));
            Optional<MembershipState> existing = MembershipState.findForComponent(currentValues, target.getId());

            debug("Target=%s (id=%s) filterGroup='%s' (id=%s) isMemberNow=%s existingEntry=%s user=%s",
                    target.getName(), target.getId(), groupName, groupId, isMemberNow,
                    existing.map(MembershipState::toValue).orElse("<none>"),
                    user.getUsername());

            if (isMemberNow && existing.isEmpty()) {
                MembershipState newState = new MembershipState(target.getId(), groupId, MembershipState.State.NEW_ADDED);
                currentValues.add(newState.toValue());
                changed = true;
                info("MARK NEW_ADDED user=%s target=%s group='%s' (id=%s)",
                        user.getUsername(), target.getName(), groupName, groupId);

            } else if (isMemberNow && existing.isPresent()
                    && existing.get().state() == MembershipState.State.NEW_DELETED) {
                // Race: user left (NEW_DELETED written) but rejoined before the sweep processed
                // the deletion. Cancel the pending deprovision and re-queue an add instead.
                // The upsert path in ScimMembershipSync is idempotent, so NEW_ADDED is safe even
                // if the user was already SENT before the leave/rejoin cycle.
                MembershipState old = existing.get();
                currentValues.remove(old.toValue());
                MembershipState newState = new MembershipState(target.getId(), groupId, MembershipState.State.NEW_ADDED);
                currentValues.add(newState.toValue());
                changed = true;
                info("CANCEL NEW_DELETED -> MARK NEW_ADDED user=%s target=%s group='%s' (id=%s) (was %s)",
                        user.getUsername(), target.getName(), groupName, groupId, old.state());

            } else if (!isMemberNow && existing.isPresent()
                    && existing.get().state() != MembershipState.State.NEW_DELETED) {
                MembershipState old = existing.get();
                currentValues.remove(old.toValue());
                MembershipState newState = new MembershipState(target.getId(), groupId, MembershipState.State.NEW_DELETED);
                currentValues.add(newState.toValue());
                changed = true;
                info("MARK NEW_DELETED user=%s target=%s group='%s' (id=%s) (was %s)",
                        user.getUsername(), target.getName(), groupName, groupId, old.state());

            } else {
                debug("No state transition needed for user=%s target=%s (isMemberNow=%s existing=%s)",
                        user.getUsername(), target.getName(), isMemberNow,
                        existing.map(MembershipState::state).orElse(null));
            }
        }

        if (changed) {
            List<String> pendingValues = computePendingValues(currentValues, scimTargets);
            persistTrackingAttributes(realm, user, currentValues, pendingValues);
        } else {
            debug("No attribute changes for user=%s.", user.getUsername());
        }

        // Group-side write path: update GroupMembershipState for each in-scope group.
        checkAndUpdateGroupMembership(realm, user, scimTargets);
    }

    /**
     * Updates GroupMembershipState attributes on all in-scope groups for the given user.
     * Called at the end of checkAndUpdateMembership so it runs for every user that the
     * user-side check already processes. Group attributes are written directly on GroupModel
     * (realm-local, not federated storage -- no UserStoragePrivateUtil needed).
     */
    private void checkAndUpdateGroupMembership(RealmModel realm, UserModel user,
                                                List<ComponentModel> scimTargets) {
        for (ComponentModel target : scimTargets) {
            if (!"true".equalsIgnoreCase(ScimTargetProviderFactory.get(
                    target, ScimTargetProviderFactory.CFG_SYNC_GROUPS, "false"))) {
                continue;
            }

            // Determine in-scope groups for this target
            List<GroupModel> inScopeGroups = resolveInScopeGroups(realm, target);
            if (inScopeGroups.isEmpty()) continue;

            // Groups the user is currently a member of, filtered to in-scope groups
            List<String> currentGroupIds = user.getGroupsStream()
                    .map(GroupModel::getId)
                    .collect(Collectors.toList());

            for (GroupModel group : inScopeGroups) {
                boolean isInGroupNow = currentGroupIds.contains(group.getId());

                List<String> stateValues = new ArrayList<>(
                        group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME).toList());

                Optional<GroupMembershipState> existing = GroupMembershipState.findForComponent(
                        stateValues, target.getId(), user.getId());

                boolean groupChanged = false;

                if (isInGroupNow && existing.isEmpty()) {
                    GroupMembershipState newEntry = new GroupMembershipState(
                            target.getId(), user.getId(), GroupMembershipState.State.NEW_ADDED);
                    stateValues.add(newEntry.toValue());
                    groupChanged = true;
                    info("GROUP MARK NEW_ADDED user=%s target=%s group='%s'",
                            user.getUsername(), target.getName(), group.getName());

                } else if (isInGroupNow && existing.isPresent()
                        && existing.get().state() == GroupMembershipState.State.NEW_DELETED) {
                    // Race guard: user left then rejoined before sweep ran.
                    // Cancel NEW_DELETED, replace with NEW_ADDED.
                    stateValues.remove(existing.get().toValue());
                    GroupMembershipState newEntry = new GroupMembershipState(
                            target.getId(), user.getId(), GroupMembershipState.State.NEW_ADDED);
                    stateValues.add(newEntry.toValue());
                    groupChanged = true;
                    info("GROUP CANCEL NEW_DELETED -> MARK NEW_ADDED user=%s target=%s group='%s' (was %s)",
                            user.getUsername(), target.getName(), group.getName(), existing.get().state());

                } else if (!isInGroupNow && existing.isPresent()
                        && existing.get().state() != GroupMembershipState.State.NEW_DELETED) {
                    stateValues.remove(existing.get().toValue());
                    GroupMembershipState newEntry = new GroupMembershipState(
                            target.getId(), user.getId(), GroupMembershipState.State.NEW_DELETED);
                    stateValues.add(newEntry.toValue());
                    groupChanged = true;
                    info("GROUP MARK NEW_DELETED user=%s target=%s group='%s' (was %s)",
                            user.getUsername(), target.getName(), group.getName(), existing.get().state());

                } else {
                    debug("GROUP no state transition for user=%s target=%s group='%s' (isInGroupNow=%s existing=%s)",
                            user.getUsername(), target.getName(), group.getName(), isInGroupNow,
                            existing.map(GroupMembershipState::state).orElse(null));
                }

                if (groupChanged) {
                    // Recompute pending flag for this target on this group
                    boolean hasPending = stateValues.stream()
                            .map(GroupMembershipState::parse)
                            .filter(Optional::isPresent)
                            .map(Optional::get)
                            .anyMatch(e -> e.componentId().equals(target.getId())
                                    && e.state() != GroupMembershipState.State.SENT);

                    List<String> allPending = new ArrayList<>(
                            group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME).toList());
                    String pendingFlag = GroupMembershipState.pendingValue(target.getId());
                    if (hasPending && !allPending.contains(pendingFlag)) {
                        allPending.add(pendingFlag);
                    } else if (!hasPending) {
                        allPending.remove(pendingFlag);
                    }

                    group.setAttribute(GroupMembershipState.ATTRIBUTE_NAME, stateValues);
                    group.setAttribute(GroupMembershipState.PENDING_ATTRIBUTE_NAME, allPending);
                    debug("Persisted group state: group='%s' target=%s membershipState=%s pending=%s",
                            group.getName(), target.getName(), stateValues, allPending);
                }
            }
        }
    }

    /**
     * Returns the list of in-scope groups for the given target.
     * When CFG_SYNC_GROUPS_FILTER is blank: only the group named by CFG_FILTER_GROUP.
     * When CFG_SYNC_GROUPS_FILTER is set: all realm groups whose name matches the regex.
     */
    private List<GroupModel> resolveInScopeGroups(RealmModel realm, ComponentModel target) {
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

    /**
     * Derives the pending work-queue values from the full membership-state list: one
     * "<componentId>:1" entry for every SCIM target that currently has an un-SENT
     * (NEW_ADDED or NEW_DELETED) entry for this user.
     */
    private List<String> computePendingValues(List<String> stateValues, List<ComponentModel> scimTargets) {
        List<String> pending = new ArrayList<>();
        for (ComponentModel target : scimTargets) {
            Optional<MembershipState> state = MembershipState.findForComponent(stateValues, target.getId());
            if (state.isPresent() && state.get().state() != MembershipState.State.SENT) {
                pending.add(MembershipState.pendingValue(target.getId()));
            }
        }
        return pending;
    }

    /**
     * Writes MembershipState.ATTRIBUTE_NAME and MembershipState.PENDING_ATTRIBUTE_NAME on
     * Keycloak's LOCAL user storage, bypassing whatever read-only/federated UserModel
     * delegate the LDAP sync machinery handed us. This is required because during LDAP
     * sync (especially with edit mode READ_ONLY, or when the built-in group-ldap-mapper
     * wraps the user), calling setAttribute(...) directly on the passed-in UserModel
     * throws org.keycloak.storage.ReadOnlyException: "Federated storage is not writable"
     * -- even though our attributes are purely local bookkeeping and have nothing to do
     * with the LDAP-mapped fields.
     */
    private void persistTrackingAttributes(RealmModel realm, UserModel user,
                                           List<String> stateValues, List<String> pendingValues) {
        UserModel localUser = UserStoragePrivateUtil.userLocalStorage(session).getUserById(realm, user.getId());
        if (localUser == null) {
            // Fallback: could not resolve a local storage reference (should not normally
            // happen since the user must already be imported locally to be enumerated
            // here). Try the delegate directly as a last resort; if the store really is
            // read-only this will throw, and we at least log why.
            info("Could not resolve local storage user for id=%s (username=%s); attempting direct setAttribute as fallback.",
                    user.getId(), user.getUsername());
            user.setAttribute(MembershipState.ATTRIBUTE_NAME, stateValues);
            user.setAttribute(MembershipState.PENDING_ATTRIBUTE_NAME, pendingValues);
            info("Persisted attributes '%s'=%s and '%s'=%s for user=%s (via federated delegate fallback)",
                    MembershipState.ATTRIBUTE_NAME, stateValues,
                    MembershipState.PENDING_ATTRIBUTE_NAME, pendingValues,
                    user.getUsername());
            return;
        }
        localUser.setAttribute(MembershipState.ATTRIBUTE_NAME, stateValues);
        localUser.setAttribute(MembershipState.PENDING_ATTRIBUTE_NAME, pendingValues);
        info("Persisted attributes '%s'=%s and '%s'=%s for user=%s (via local storage)",
                MembershipState.ATTRIBUTE_NAME, stateValues,
                MembershipState.PENDING_ATTRIBUTE_NAME, pendingValues,
                user.getUsername());
    }

    /* ===== Required LDAPStorageMapper methods (no-ops, this mapper only observes) ===== */

    @Override
    public void close() { }

    @Override
    public void onRegisterUserToLDAP(LDAPObject ldapUser, UserModel localUser, RealmModel realm) { }

    @Override
    public LDAPStorageProvider getLdapProvider() { return null; }

    @Override
    public boolean onAuthenticationFailure(LDAPObject ldapUser, UserModel user,
                                           AuthenticationException ldapException, RealmModel realm) {
        return false;
    }

    @Override
    public void beforeLDAPQuery(LDAPQuery query) { }

    @Override
    public java.util.Set<String> mandatoryAttributeNames() { return java.util.Collections.emptySet(); }

    @Override
    public java.util.Set<String> getUserAttributes() { return java.util.Collections.emptySet(); }

    @Override
    public UserModel proxy(LDAPObject ldapUser, UserModel delegate, RealmModel realm) { return delegate; }

    @Override
    public List<UserModel> getRoleMembers(RealmModel realm, org.keycloak.models.RoleModel role,
                                          int firstResult, int maxResults) {
        // Must return an empty list, never null: Keycloak's LDAP federation layer
        // aggregates getRoleMembers()/getGroupMembers() results across ALL mappers
        // registered on the provider. Returning null here breaks that aggregation
        // and can wipe out group/role member listings contributed by other mappers
        // (e.g. the built-in group-ldap-mapper) once this mapper is added to the chain.
        return java.util.Collections.emptyList();
    }

    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group,
                                           int firstResult, int maxResults) {
        // See note on getRoleMembers() above -- never return null here.
        return java.util.Collections.emptyList();
    }

    @Override
    public SynchronizationResult syncDataFromFederationProviderToKeycloak(RealmModel realm) {
        // Keycloak invokes this on EVERY LDAP sync run for EVERY registered mapper --
        // including frequent delta ("changed users") syncs -- so it must stay cheap.
        // In LDAP_ONLY (or READ_ONLY) mode, the built-in group-ldap-mapper computes
        // group membership live from LDAP and does NOT route changes through
        // onImportUserFromLDAP, so this is our only reliable hook in that mode. But we
        // must NOT iterate every user in the realm here (that was the original
        // performance problem, e.g. 941 users scanned on every single sync). Instead we
        // build a small targeted candidate set -- see buildCandidateUsers() -- and only
        // re-run the membership diff for those users.
        List<ComponentModel> scimTargets = realm.getComponentsStream()
                .filter(c -> ScimTargetProviderFactory.ID.equals(c.getProviderId()))
                .toList();

        if (scimTargets.isEmpty()) {
            debug("No SCIM outbound targets configured in realm=%s. Skipping sweep.", realm.getName());
            return new SynchronizationResult();
        }

        Map<String, UserModel> candidates = buildCandidateUsers(realm, scimTargets);
        info("syncDataFromFederationProviderToKeycloak fired for realm=%s -- checking %d targeted candidate(s) instead of full realm scan.",
                realm.getName(), candidates.size());

        int usersChecked = 0;
        for (UserModel user : candidates.values()) {
            usersChecked++;
            checkAndUpdateMembership(realm, user);
        }
        info("Targeted membership check done for realm=%s: usersChecked=%d", realm.getName(), usersChecked);
        return new SynchronizationResult();
    }

    /**
     * Builds the set of users that could possibly need a membership-state transition,
     * without ever enumerating every user in the realm:
     *
     * 1. Users CURRENTLY in one of the configured filter groups. Looked up via
     *    session.users().getGroupMembersStream(realm, group), which for an
     *    LDAP-federated group delegates to the built-in group-ldap-mapper's own
     *    group-scoped LDAP query (filtered to just that group's members) rather than
     *    a realm-wide scan. Catches new joins.
     *
     * 2. Users with an outstanding pending flag for any target (indexed attribute
     *    search on MembershipState.PENDING_ATTRIBUTE_NAME). Catches users whose last
     *    known transition (NEW_ADDED/NEW_DELETED) has not yet been confirmed/re-synced.
     *
     * 3. Users we last recorded as an active/SENT member of a target (indexed
     *    attribute search on MembershipState.ATTRIBUTE_NAME for the exact JSON
     *    sentinel value). This is what lets us detect a user who just LEFT the group:
     *    they will no longer show up in (1), but we still need to re-check them so
     *    their state can flip to NEW_DELETED.
     *
     * The union of (1) + (2) + (3) is exactly the population that can possibly have
     * changed since the last sync; everyone else is provably unchanged.
     */
    private Map<String, UserModel> buildCandidateUsers(RealmModel realm, List<ComponentModel> scimTargets) {
        Map<String, UserModel> candidates = new LinkedHashMap<>();

        for (ComponentModel target : scimTargets) {
            String groupName = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
            if (groupName == null || groupName.isBlank()) {
                continue;
            }

            // (1) currently in the group -- group-scoped lookup, not a realm-wide scan.
            // This one legitimately goes through the aggregated session.groups()/
            // session.users(), since group membership itself is LDAP-backed.
            session.groups().searchForGroupByNameStream(realm, groupName, true, null, null)
                    .forEach(group -> session.users().getGroupMembersStream(realm, group)
                            .forEach(u -> candidates.putIfAbsent(u.getId(), u)));

            // (2) and (3) search our own tracking attributes (MembershipState.*), which
            // are purely local bookkeeping and were never mapped into LDAP. Calling
            // searchForUserByUserAttributeStream(...) on the aggregated session.users()
            // (UserStorageManager) fans the query out to EVERY enabled user storage
            // provider capable of attribute search -- including the AD/LDAP federation
            // provider -- which then tries to build a native LDAP filter using our
            // attribute name (e.g. "ldapSyncNotifier.pending=..."). AD has no such
            // attribute, so this throws
            // javax.naming.directory.InvalidSearchFilterException: "invalid attribute
            // description". We must query LOCAL storage only, via
            // UserStoragePrivateUtil.userLocalStorage(session), exactly as we already do
            // for the writes in persistTrackingAttributes(...).

            // (2) currently pending for this target -- indexed attribute search, local storage only.
            UserStoragePrivateUtil.userLocalStorage(session)
                    .searchForUserByUserAttributeStream(realm,
                            MembershipState.PENDING_ATTRIBUTE_NAME,
                            MembershipState.pendingValue(target.getId()))
                    .forEach(u -> candidates.putIfAbsent(u.getId(), u));

            // (3) last known as an active (SENT) member of this target -- indexed
            // attribute search on the exact tracked JSON value, so we can detect
            // departures. We need the group's stable ID to reconstruct the sentinel.
            // Local storage only, for the same reason as (2) above.
            session.groups().searchForGroupByNameStream(realm, groupName, true, null, null)
                    .findFirst()
                    .ifPresent(group -> {
                        String sentValue = new MembershipState(
                                target.getId(), group.getId(), MembershipState.State.SENT).toValue();
                        UserStoragePrivateUtil.userLocalStorage(session)
                                .searchForUserByUserAttributeStream(realm,
                                        MembershipState.ATTRIBUTE_NAME, sentValue)
                                .forEach(u -> candidates.putIfAbsent(u.getId(), u));
                    });
        }
        return candidates;
    }

    @Override
    public SynchronizationResult syncDataFromKeycloakToFederationProvider(RealmModel realm) {
        return new SynchronizationResult();
    }

    /* ===== logging ===== */

    private static void debug(String fmt, Object... args) {
        System.out.printf("%s %s DEBUG %s%n", now(), LOG_TAG, String.format(fmt, args));
    }

    private static void info(String fmt, Object... args) {
        System.out.printf("%s %s INFO %s%n", now(), LOG_TAG, String.format(fmt, args));
    }

    private static void err(String fmt, Object... args) {
        System.out.printf("%s %s ERROR %s%n", now(), LOG_TAG, String.format(fmt, args));
    }

    private static String now() {
        return java.time.OffsetDateTime.now().toString();
    }
}
