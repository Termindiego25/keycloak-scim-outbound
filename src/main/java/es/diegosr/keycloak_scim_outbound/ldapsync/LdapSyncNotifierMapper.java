package es.diegosr.keycloak_scim_outbound.ldapsync;

import es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.mappers.LDAPStorageMapper;
import org.keycloak.storage.user.SynchronizationResult;

import javax.naming.AuthenticationException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * LDAP Storage Mapper that has NO knowledge of SCIM push logic. Its only job is to
 * record, per SCIM outbound target (identified by ComponentModel id), whether the user
 * is currently a member of that target's configured CFG_FILTER_GROUP, and flag a
 * pending state change ("NEW_ADDED" / "NEW_DELETED") whenever that membership differs
 * from what was last recorded.
 *
 * This mapper is invoked by Keycloak's LDAP federation provider during BOTH:
 *   - manual "Synchronize all users" / "Synchronize changed users" actions, and
 *   - periodic background sync (full or changed-users-only),
 * neither of which fire a normal Event/AdminEvent for group membership changes.
 *
 * IMPORTANT: this mapper must be ordered AFTER the built-in "group-ldap-mapper" in the
 * LDAP provider's Mappers list, so that user.getGroupsStream() already reflects the
 * group membership computed during this same sync pass. See README for setup.
 *
 * The actual SCIM push happens elsewhere (ScimMembershipSync), triggered by a timer or
 * by the SCIM target's own "Synchronize" action -- this class never calls out to SCIM.
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
            user.setAttribute(MembershipState.ATTRIBUTE_NAME, currentValues);
            info("Persisted attribute '%s' for user=%s -> %s", MembershipState.ATTRIBUTE_NAME, user.getUsername(), currentValues);
        } else {
            debug("No attribute changes for user=%s.", user.getUsername());
        }
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
