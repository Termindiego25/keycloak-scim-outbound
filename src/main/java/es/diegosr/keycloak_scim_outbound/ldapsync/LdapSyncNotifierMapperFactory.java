package es.diegosr.keycloak_scim_outbound.ldapsync;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.storage.ldap.mappers.LDAPStorageMapperFactory;

import java.util.Collections;
import java.util.List;

/**
 * Registers the "LDAP Sync Notifier" mapper as a selectable mapper type under
 * Realm -> User Federation -> (your LDAP provider) -> Mappers -> Create.
 *
 * IMPORTANT (see README): add this mapper AFTER the built-in "group-ldap-mapper"
 * in the mapper list so it observes final group membership for the current sync pass.
 */
public class LdapSyncNotifierMapperFactory implements LDAPStorageMapperFactory<LdapSyncNotifierMapper> {

    public static final String ID = "ldap-sync-notifier";

    @Override
    public LdapSyncNotifierMapper create(KeycloakSession session, ComponentModel model) {
        return new LdapSyncNotifierMapper(session, model);
    }

    @Override
    public String getId() {
        return ID;
    }

    public String getHelpText() {
        return "Tracks per-user membership in keycloak-scim-outbound filter groups across LDAP syncs "
                + "(manual and periodic), since Keycloak does not fire Event/AdminEvent for LDAP-driven "
                + "group membership changes. Must be added AFTER the group-ldap-mapper.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }
}
