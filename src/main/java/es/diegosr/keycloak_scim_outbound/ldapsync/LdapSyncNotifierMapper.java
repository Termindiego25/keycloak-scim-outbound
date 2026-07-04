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
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * LDAP Storage Mapper that has NO knowledge of SCIM push logic. Its only job is to
 * record, per SCIM outbound target (identified by ComponentModel id), whether the user
 * is currently a member of that target's configured CFG_FILTER_GROUP, and flag a
 * pending state change ("NEW_ADDED" / "NEW_DELETED") whenever that membership differs
 * from what was last recorded.
 *
 * There are TWO entry points that can trigger this check, because Keycloak's LDAP
 * federation layer does not consistently notify per-user mappers of group membership
 * changes -- it depends on the built-in group-ldap-mapper's configured Mode:
 *
 *   - onImportUserFromLDAP(...): fires per user during "Synchronize all/changed users"
 *     ONLY when the group-ldap-mapper is running in IMPORT mode (membership gets
 *     written into Keycloak's local user/group tables during per-user import).
 *
 *   - syncDataFromFederationProviderToKeycloak(...): fires once per full LDAP sync run.
 *     This is the ONLY reliable hook when group-ldap-mapper is in LDAP_ONLY (or
 *     READ_ONLY) mode, because in that mode membership is computed live from LDAP via
 *     user.getGroupsStream() and never routed through the per-user import callback.
 *     We use this hook to iterate all local users ourselves and re-run the same
 *     membership diff logic.
 *
 * IMPORTANT: this mapper must be ordered AFTER the built-in "group-ldap-mapper" in the
 * LDAP provider's Mappers list, so that user.getGroupsStream() already reflects the
 * group membership computed during this same sync pass. See README for setup.
 *
 * The actual SCIM push happens elsewhere (ScimMembershipSync), triggered by a timer or
 * by the SCIM target's own "Synchronize" action -- this class never calls out to SCIM.
 *
 * WRITE SAFETY: when the LDAP provider's edit mode is READ_ONLY (or the built-in
 * group-ldap-mapper mode causes Keycloak to wrap the user in a
 * ReadonlyLDAPUserModelDelegate during sync), calling setAttribute(...) directly on the
 * UserModel passed in by the LDAP sync machinery throws
 * org.keycloak.storage.ReadOnlyException: "Federated storage is not writable". Our
 * tracking attribute (MembershipState.ATTRIBUTE_NAME) is a purely local bookkeeping
 * value that has nothing to do with LDAP, so we must bypass that read-only delegate
 * and write it directly on Keycloak's LOCAL user storage instead, via
 * UserStoragePrivateUtil.userLocalStorage(session).
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
     * and updates the tracking attribute if anything changed. Shared by both
     * onImportUserFromLDAP (IMPORT mode) and the full-sync sweep below (LDAP_ONLY mode).
     */
    private void checkAndUpdateMembership(RealmModel realm, UserModel user) {
        List<ComponentModel> scimTargets = realm.getComponentsStream()
                .filter(c -> ScimTargetProviderFactory.ID.equals(c.getProviderId()))
                .toList();

        if (scimTargets.isEmpty()) {
            debug("No SCIM outbound targets configured in realm=%s. Nothing to do for user=%s.", realm.getName(), user.getUsername());
            return;
        }

        List<String> currentValues = new ArrayList<>(
                user.getAttributeStream(MembershipState.ATTRIBUTE_NAME).toList());

        boolean changed = false;

        for (ComponentModel target : scimTargets) {
            String groupName = ScimTargetProviderFactory.get(target, ScimTargetProviderFactory.CFG_FILTER_GROUP, null);
            if (groupName == null || groupName.isBlank()) {
                debug("Target=%s has no CFG_FILTER_GROUP configured. Skipping for user=%s.", target.getName(), user.getUsername());
                continue;
            }

            boolean isMemberNow = user.getGroupsStream().anyMatch(g -> groupName.equals(g.getName()));
            Optional<MembershipState> existing = MembershipState.findForComponent(currentValues, target.getId());

            debug("Target=%s (id=%s) filterGroup='%s' isMemberNow=%s existingEntry=%s user=%s",
                    target.getName(), target.getId(), groupName, isMemberNow,
                    existing.map(MembershipState::toValue).orElse("<none>"), user.getUsername());

            if (isMemberNow && existing.isEmpty()) {
                MembershipState newState = new MembershipState(target.getId(), groupName, MembershipState.State.NEW_ADDED);
                currentValues.add(newState.toValue());
                changed = true;
                info("MARK NEW_ADDED user=%s target=%s group='%s'", user.getUsername(), target.getName(), groupName);

            } else if (!isMemberNow && existing.isPresent()
                    && existing.get().state() != MembershipState.State.NEW_DELETED) {
                MembershipState old = existing.get();
                currentValues.remove(old.toValue());
                MembershipState newState = new MembershipState(target.getId(), groupName, MembershipState.State.NEW_DELETED);
                currentValues.add(newState.toValue());
                changed = true;
                info("MARK NEW_DELETED user=%s target=%s group='%s' (was %s)", user.getUsername(), target.getName(), groupName, old.state());

            } else {
                debug("No state transition needed for user=%s target=%s (isMemberNow=%s existing=%s)",
                        user.getUsername(), target.getName(), isMemberNow, existing.map(MembershipState::state).orElse(null));
            }
        }

        if (changed) {
            persistTrackingAttribute(realm, user, currentValues);
        } else {
            debug("No attribute changes for user=%s.", user.getUsername());
        }
    }

    /**
     * Writes MembershipState.ATTRIBUTE_NAME on Keycloak's LOCAL user storage, bypassing
     * whatever read-only/federated UserModel delegate the LDAP sync machinery handed us.
     * This is required because during LDAP sync (especially with edit mode READ_ONLY,
     * or when the built-in group-ldap-mapper wraps the user), calling setAttribute(...)
     * directly on the passed-in UserModel throws
     * org.keycloak.storage.ReadOnlyException: "Federated storage is not writable" --
     * even though our attribute is purely local bookkeeping and has nothing to do with
     * the LDAP-mapped fields.
     */
    private void persistTrackingAttribute(RealmModel realm, UserModel user, List<String> values) {
        UserModel localUser = UserStoragePrivateUtil.userLocalStorage(session).getUserById(realm, user.getId());

        if (localUser == null) {
            // Fallback: could not resolve a local storage reference (should not normally
            // happen since the user must already be imported locally to be enumerated
            // here). Try the delegate directly as a last resort; if the store really is
            // read-only this will throw, and we at least log why.
            info("Could not resolve local storage user for id=%s (username=%s); attempting direct setAttribute as fallback.",
                    user.getId(), user.getUsername());
            user.setAttribute(MembershipState.ATTRIBUTE_NAME, values);
            info("Persisted attribute '%s' for user=%s -> %s (via federated delegate fallback)",
                    MembershipState.ATTRIBUTE_NAME, user.getUsername(), values);
            return;
        }

        localUser.setAttribute(MembershipState.ATTRIBUTE_NAME, values);
        info("Persisted attribute '%s' for user=%s -> %s (via local storage)",
                MembershipState.ATTRIBUTE_NAME, user.getUsername(), values);
    }

    /* ===== Required LDAPStorageMapper methods (no-ops, this mapper only observes) ===== */

    @Override
    public void close() { }

    @Override
    public void onRegisterUserToLDAP(LDAPObject ldapUser, UserModel localUser, RealmModel realm) { }

    @Override
    public LDAPStorageProvider getLdapProvider() { return null; }

    @Override
    public boolean onAuthenticationFailure(LDAPObject ldapUser, UserModel user, AuthenticationException ldapException, RealmModel realm) {
        return false;
    }

    @Override
    public void beforeLDAPQuery(LDAPQuery query) { }

    @Override
    public java.util.Set<String> mandatoryAttributeNames() {
        return java.util.Collections.emptySet();
    }

    @Override
    public java.util.Set<String> getUserAttributes() {
        return java.util.Collections.emptySet();
    }

    @Override
    public UserModel proxy(LDAPObject ldapUser, UserModel delegate, RealmModel realm) {
        return delegate;
    }

    @Override
    public List<UserModel> getRoleMembers(RealmModel realm, org.keycloak.models.RoleModel role, int firstResult, int maxResults) {
        // Must return an empty list, never null: Keycloak's LDAP federation layer
        // aggregates getRoleMembers()/getGroupMembers() results across ALL mappers
        // registered on the provider. Returning null here breaks that aggregation
        // and can wipe out group/role member listings contributed by other mappers
        // (e.g. the built-in group-ldap-mapper) once this mapper is added to the chain.
        return java.util.Collections.emptyList();
    }

    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group, int firstResult, int maxResults) {
        // See note on getRoleMembers() above -- never return null here.
        return java.util.Collections.emptyList();
    }

    @Override
    public SynchronizationResult syncDataFromFederationProviderToKeycloak(RealmModel realm) {
        // In LDAP_ONLY (or READ_ONLY) mode, the built-in group-ldap-mapper computes
        // group membership live from LDAP and does NOT route changes through
        // onImportUserFromLDAP. This is the only reliable hook we get for a full sync
        // in that mode, so we iterate all local users here and re-run the same
        // membership diff logic used in onImportUserFromLDAP.
        info("syncDataFromFederationProviderToKeycloak fired for realm=%s -- running full membership sweep.", realm.getName());

        List<ComponentModel> scimTargets = realm.getComponentsStream()
                .filter(c -> ScimTargetProviderFactory.ID.equals(c.getProviderId()))
                .toList();

        if (scimTargets.isEmpty()) {
            debug("No SCIM outbound targets configured in realm=%s. Skipping full sweep.", realm.getName());
            return new SynchronizationResult();
        }

        int usersChecked = 0;
        List<UserModel> allUsers = session.users().searchForUserStream(realm, Map.of()).toList();
        for (UserModel user : allUsers) {
            usersChecked++;
            checkAndUpdateMembership(realm, user);
        }

        info("Full membership sweep done for realm=%s: usersChecked=%d", realm.getName(), usersChecked);
        return new SynchronizationResult();
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
        System.out.printf("%s %s INFO  %s%n", now(), LOG_TAG, String.format(fmt, args));
    }

    private static String now() {
        return java.time.OffsetDateTime.now().toString();
    }
}
