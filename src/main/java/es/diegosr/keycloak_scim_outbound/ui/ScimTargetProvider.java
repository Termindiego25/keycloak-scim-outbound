package es.diegosr.keycloak_scim_outbound.ui;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.storage.UserStorageProvider;

/**
 * We don't store users; this "UserStorageProvider" only exists so we can
 * have a UI-configurable component under "User Federation" that the
 * EventListener can read for SCIM target configuration.
 */
public class ScimTargetProvider implements UserStorageProvider {
    private final KeycloakSession session;
    private final ComponentModel model;

    public ScimTargetProvider(KeycloakSession session, ComponentModel model) {
        this.session = session;
        this.model = model;
    }

    public ComponentModel getModel() { return model; }

    @Override public void close() { }
}