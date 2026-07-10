package es.diegosr.keycloak_scim_outbound;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class ScimEventListenerProviderFactory implements EventListenerProviderFactory {

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new ScimEventListenerProvider(session);
    }

    @Override public void init(Config.Scope config) { }

    /**
     * Timer-based periodic sweep removed. The native Keycloak sync provider already
     * exposes a configurable sync interval in the admin console (User Federation ->
     * provider -> Sync Settings). Admins configure the interval there. The old 5-minute
     * hardcoded timer was redundant and has been removed.
     */
    @Override
    public void postInit(KeycloakSessionFactory factory) { }

    @Override public void close() { }

    @Override
    public String getId() {
        return "keycloak-scim-outbound";
    }
}
