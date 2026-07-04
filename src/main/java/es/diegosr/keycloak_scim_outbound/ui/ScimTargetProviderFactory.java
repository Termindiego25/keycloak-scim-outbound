package es.diegosr.keycloak_scim_outbound.ui;

import es.diegosr.keycloak_scim_outbound.ldapsync.ScimMembershipSync;

import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.user.ImportSynchronization;
import org.keycloak.storage.user.SynchronizationResult;

import java.util.Date;
import java.util.List;

/**
 * UI-configurable provider (shows up under: Realm -> User Federation -> Add provider).
 * This does not store users; it only holds SCIM target configuration so the event listener
 * can read it and push SCIM operations accordingly.
 *
 * Implements ImportSynchronization so that clicking "Synchronize all users" /
 * "Synchronize changed users" on this provider's page in the admin console triggers
 * an immediate sweep of pending LDAP-driven membership changes for THIS target only,
 * instead of waiting for the next 5-minute timer tick.
 */
public class ScimTargetProviderFactory implements UserStorageProviderFactory<ScimTargetProvider>, ImportSynchronization {

    private static final String LOG_TAG = "[keycloak-scim-outbound/MANUAL-SYNC]";

    /** Stable provider id shown in the "Add provider" list. Keep this in sync with the listener lookup. */
    public static final String ID = "keycloak-scim-outbound";

    /** Config keys stored in ComponentModel#getConfig(). */
    public static final String CFG_BASE_URL       = "baseUrl";
    public static final String CFG_TOKEN          = "token";
    public static final String CFG_FILTER_GROUP   = "filterGroup";       // optional

    /** How to build SCIM userName: username | email | attribute */
    public static final String CFG_UNAME_STRATEGY = "userNameStrategy";
    /** Attribute name when strategy=attribute */
    public static final String CFG_UNAME_ATTR     = "userNameAttribute";

    /** Deprovisioning behavior on delete / group removal: deactivate | delete */
    public static final String CFG_DEPROVISION    = "deprovisionAction";

    private static ProviderConfigProperty list(String help, String name, List<String> options, String def, boolean required) {
        ProviderConfigProperty p = new ProviderConfigProperty();
        p.setType(ProviderConfigProperty.LIST_TYPE);
        p.setName(name);
        p.setLabel(name);
        p.setHelpText(help);
        p.setOptions(options);
        p.setDefaultValue(def);
        p.setRequired(required);
        return p;
    }

    private static final List<ProviderConfigProperty> PROPS = List.of(
        prop(ProviderConfigProperty.STRING_TYPE,  CFG_BASE_URL,
            "SCIM Base URL (e.g. https://app.example.com/scim/v2).", true, "SCIM Base URL"),
        prop(ProviderConfigProperty.PASSWORD,     CFG_TOKEN,
            "SCIM Bearer token used to authenticate against the target.", true, "SCIM Token"),
        prop(ProviderConfigProperty.STRING_TYPE,  CFG_FILTER_GROUP,
            "Optional group filter. If set, only users in this Keycloak group will be provisioned.", false, "Filter Group (optional)"),

        list("How to build SCIM 'userName': 'username' (Keycloak username), 'email', or a custom user attribute.",
            CFG_UNAME_STRATEGY, List.of("username","email","attribute"), "username", true),

        prop(ProviderConfigProperty.STRING_TYPE,  CFG_UNAME_ATTR,
            "User attribute name to read when 'userNameStrategy=attribute' (e.g. scim_username).", false, "UserName Attribute"),

        list("Deprovisioning behavior when a user is deleted or removed from the filter group: "
            + "'deactivate' (PATCH active=false, default) or 'delete' (DELETE /Users/{id}, e.g. for vCenter).",
            CFG_DEPROVISION, List.of("deactivate","delete"), "deactivate", true)
    );

    @Override
    public ScimTargetProvider create(KeycloakSession session, ComponentModel model) {
        return new ScimTargetProvider(session, model);
    }

    @Override
    public String getId() {
        return ID;
    }

    /** Not all KC versions declare this in the interface; leave without @Override on purpose. */
    public String getHelpText() {
        return "Push users to an external SCIM endpoint (Passbolt, Nextcloud, ...) with optional group filtering.";
    }

    @Override public void init(org.keycloak.Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model)
            throws ComponentValidationException {
        require(model, CFG_BASE_URL, "SCIM Base URL is required");
        require(model, CFG_TOKEN,    "SCIM token is required");

        String base = get(model, CFG_BASE_URL, "");
        if (!base.startsWith("http://") && !base.startsWith("https://")) {
            throw new ComponentValidationException("SCIM Base URL must start with http:// or https://");
        }

        String strategy = get(model, CFG_UNAME_STRATEGY, "username");
        switch (strategy) {
            case "username":
            case "email":
                break;
            case "attribute":
                require(model, CFG_UNAME_ATTR, "When userNameStrategy=attribute, 'userNameAttribute' is required");
                break;
            default:
                throw new ComponentValidationException("Invalid userNameStrategy. Use 'username', 'email', or 'attribute'.");
        }

        String deprovision = get(model, CFG_DEPROVISION, "deactivate");
        if (!"deactivate".equals(deprovision) && !"delete".equals(deprovision)) {
            throw new ComponentValidationException("Invalid deprovisionAction. Use 'deactivate' or 'delete'.");
        }
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return PROPS;
    }

    /* ===== ImportSynchronization: triggered by the "Synchronize" buttons in the admin console =====
     * NOTE: Keycloak's ImportSynchronization interface takes UserStorageProviderModel (not the
     * plain ComponentModel) as the last parameter -- see org.keycloak.storage.user.ImportSynchronization
     * in keycloak-server-spi-private for the exact signature. */

    @Override
    public SynchronizationResult sync(KeycloakSessionFactory sessionFactory, String realmId, UserStorageProviderModel model) {
        info("Manual 'Synchronize all users' triggered for target=%s (componentId=%s) realm=%s",
                model.getName(), model.getId(), realmId);
        return runSweep(sessionFactory, realmId, model);
    }

    @Override
    public SynchronizationResult syncSince(Date lastSync, KeycloakSessionFactory sessionFactory, String realmId, UserStorageProviderModel model) {
        info("Manual 'Synchronize changed users' triggered for target=%s (componentId=%s) realm=%s lastSync=%s",
                model.getName(), model.getId(), realmId, lastSync);
        // We don't have an incremental changed-users query for our own attribute state,
        // so we just run the same full pending-entries sweep, scoped to this component.
        return runSweep(sessionFactory, realmId, model);
    }

    private SynchronizationResult runSweep(KeycloakSessionFactory sessionFactory, String realmId, ComponentModel model) {
        long start = System.currentTimeMillis();
        try {
            KeycloakModelUtils.runJobInTransaction(sessionFactory, session -> {
                RealmModel realm = session.realms().getRealm(realmId);
                if (realm == null) {
                    err("Realm not found for realmId=%s during manual sync of target=%s", realmId, model.getName());
                    return;
                }
                ScimMembershipSync.processPendingMembershipChanges(session, realm, model.getId());
            });
            info("Manual sync for target=%s completed in %dms", model.getName(), System.currentTimeMillis() - start);
        } catch (Exception e) {
            err("Manual sync for target=%s FAILED: %s", model.getName(), e.getMessage());
            SynchronizationResult failed = new SynchronizationResult();
            failed.setFailed(1);
            return failed;
        }
        SynchronizationResult result = new SynchronizationResult();
        return result;
    }

    /* ===== Helpers ===== */

    private static ProviderConfigProperty prop(String type, String name, String help,
                                               boolean required, String label) {
        ProviderConfigProperty p = new ProviderConfigProperty();
        p.setType(type);
        p.setName(name);
        p.setLabel(label != null ? label : name);
        p.setHelpText(help);
        p.setDefaultValue(null);
        p.setSecret(ProviderConfigProperty.PASSWORD.equals(type)); // hide token in UI
        p.setRequired(required);
        return p;
    }

    private static void require(ComponentModel model, String key, String msg)
            throws ComponentValidationException {
        String v = get(model, key, null);
        if (v == null || v.isBlank()) {
            throw new ComponentValidationException(msg);
        }
    }

    public static String get(ComponentModel m, String key, String def) {
        String v = m.getConfig().getFirst(key);
        return v != null ? v : def;
    }

    /* ===== logging ===== */

    private static String now() {
        return java.time.OffsetDateTime.now().toString();
    }

    private static void info(String fmt, Object... args) {
        System.out.printf("%s %s INFO  %s%n", now(), LOG_TAG, String.format(fmt, args));
    }

    private static void err(String fmt, Object... args) {
        System.err.printf("%s %s ERROR %s%n", now(), LOG_TAG, String.format(fmt, args));
    }
}
