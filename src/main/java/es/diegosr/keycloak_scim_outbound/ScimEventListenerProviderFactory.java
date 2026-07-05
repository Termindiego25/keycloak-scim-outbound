package es.diegosr.keycloak_scim_outbound;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory for the SCIM outbound event listener.
 *
 * Periodic sync (full and changed-users) is driven entirely by Keycloak's built-in
 * "Sync Settings" scheduler on the ScimTargetProviderFactory (ImportSynchronization).
 * Keycloak calls sync() for "Synchronize all users" / periodic full sync, and
 * syncSince() for "Synchronize changed users" / periodic changed-users sync.
 *
 * The previous custom TimerProvider-based 5-minute sweep has been removed; the
 * Keycloak scheduler is the only periodic driver.
 */
public class ScimEventListenerProviderFactory implements EventListenerProviderFactory {

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new ScimEventListenerProvider(session);
    }

    @Override public void init(Config.Scope config) { }

    @Override public void postInit(KeycloakSessionFactory factory) { }

    @Override public void close() { }

    @Override
    public String getId() {
        return "keycloak-scim-outbound";
    }
}
