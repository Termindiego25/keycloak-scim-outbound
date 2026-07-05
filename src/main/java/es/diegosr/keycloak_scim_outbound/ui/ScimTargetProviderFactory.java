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
 * Implements ImportSynchronization so that Keycloak's built-in "Sync Settings" scheduler
 * drives periodic sync without a custom timer:
 *
 *   sync()      -- "Synchronize all users" button / Periodic Full Sync toggle:
 *                  Upserts every in-scope user and group unconditionally.
 *                  Optionally reconciles stale SCIM entries (CFG_RECONCILE_USERS /
 *                  CFG_RECONCILE_GROUPS) by querying GET /Users and GET /Groups and
 *                  deprovisioning any entry whose externalId is no longer in scope.
 *
 *   syncSince() -- "Synchronize changed users" button / Periodic Changed Users Sync toggle:
 *                  Consumes the pending-attribute bookkeeping written by LdapSyncNotifierMapper
 *                  and pushes only users/groups that are flagged as changed.
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

    /** When "true", SCIM /Groups resources are created/updated/deleted in addition to users. */
    public static final String CFG_PROVISION_GROUPS = "provisionGroups";

    /**
     * Comma-separated list of Keycloak group names to sync as SCIM Groups.
     * Blank = sync the group already named in CFG_FILTER_GROUP (if any).
     * Only meaningful when CFG_PROVISION_GROUPS=true.
     */
    public static final String CFG_GROUP_FILTER = "groupFilter";

    /**
     * When "true", a full sync queries GET /Users from the SCIM target and deprovisions
     * any user whose externalId is not in the current in-scope Keycloak set.
     * Disable for SCIM providers that do not support listing /Users.
     */
    public static final String CFG_RECONCILE_USERS = "reconcileUsers";

    /**
     * When "true", a full sync queries GET /Groups from the SCIM target and deletes
     * any group whose externalId is not in the current in-scope Keycloak group set.
     * Disable for SCIM providers that do not support listing /Groups.
     * Only meaningful when CFG_PROVISION_GROUPS=true.
     */
    public static final String CFG_RECONCILE_GROUPS = "reconcileGroups";

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
            CFG_DEPROVISION, List.of("deactivate","delete"), "deactivate", true),

        prop(ProviderConfigProperty.BOOLEAN_TYPE, CFG_PROVISION_GROUPS,
            "When enabled, a SCIM /Groups resource is kept in sync for each Keycloak group that "
            + "falls within the configured filter. Members are reconciled on every sync.",
            false, "Provision Groups"),

        prop(ProviderConfigProperty.STRING_TYPE, CFG_GROUP_FILTER,
            "Comma-separated Keycloak group names to provision as SCIM Groups (e.g. admins,devs). "
            + "Leave blank to use the same group as the user filter (Filter Group). "
            + "Only evaluated when 'Provision Groups' is enabled.",
            false, "Group Sync Filter (optional)"),

        prop(ProviderConfigProperty.BOOLEAN_TYPE, CFG_RECONCILE_USERS,
            "During a full sync, query GET /Users from the SCIM target and deprovision any user "
            + "whose externalId is no longer in the in-scope Keycloak set. "
            + "Disable if the SCIM provider does not support listing /Users.",
            false, "Reconcile Users (full sync)"),

        prop(ProviderConfigProperty.BOOLEAN_TYPE, CFG_RECONCILE_GROUPS,
            "During a full sync, query GET /Groups from the SCIM target and delete any group "
            + "whose externalId is no longer in the in-scope Keycloak group set. "
            + "Only meaningful when 'Provision Groups' is enabled. "
            + "Disable if the SCIM provider does not support listing /Groups.",
            false, "Reconcile Groups (full sync)")
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

    /* ===== ImportSynchronization =====
     * NOTE: Keycloak's ImportSynchronization interface takes UserStorageProviderModel (not the
     * plain ComponentModel) as the last parameter -- see org.keycloak.storage.user.ImportSynchronization
     * in keycloak-server-spi-private for the exact signature. */

    /**
     * Called by:
     *   - "Synchronize all users" button in the admin console
     *   - Keycloak's "Periodic Full Sync" scheduler (when enabled in Sync Settings)
     *
     * Performs a full sync: upserts every in-scope user and group unconditionally,
     * then optionally reconciles stale SCIM entries (CFG_RECONCILE_USERS / CFG_RECONCILE_GROUPS).
     */
    @Override
    public SynchronizationResult sync(KeycloakSessionFactory sessionFactory, String realmId, UserStorageProviderModel model) {
        info("Full sync triggered for target=%s (componentId=%s) realm=%s",
                model.getName(), model.getId(), realmId);
        return runFullSync(sessionFactory, realmId, model);
    }

    /**
     * Called by:
     *   - "Synchronize changed users" button in the admin console
     *   - Keycloak's "Periodic Changed Users Sync" scheduler (when enabled in Sync Settings)
     *
     * Performs a changed-users sweep: consumes the pending-attribute bookkeeping written by
     * LdapSyncNotifierMapper and pushes only users/groups that are flagged as changed since
     * the last LDAP sync.
     */
    @Override
    public SynchronizationResult syncSince(Date lastSync, KeycloakSessionFactory sessionFactory, String realmId, UserStorageProviderModel model) {
        info("Changed-users sync triggered for target=%s (componentId=%s) realm=%s lastSync=%s",
                model.getName(), model.getId(), realmId, lastSync);
        return runPendingSweep(sessionFactory, realmId, model);
    }

    private SynchronizationResult runFullSync(KeycloakSessionFactory sessionFactory, String realmId, ComponentModel model) {
        long start = System.currentTimeMillis();
        final int[] counts = {0, 0}; // [added, failed]
        try {
            KeycloakModelUtils.runJobInTransaction(sessionFactory, session -> {
                RealmModel realm = session.realms().getRealm(realmId);
                if (realm == null) {
                    err("Realm not found for realmId=%s during full sync of target=%s", realmId, model.getName());
                    return;
                }
                session.getContext().setRealm(realm);
                int[] result = ScimMembershipSync.fullSync(session, realm, model.getId());
                counts[0] = result[0];
                counts[1] = result[1];
            });
            info("Full sync for target=%s completed in %dms (added=%d failed=%d)",
                    model.getName(), System.currentTimeMillis() - start, counts[0], counts[1]);
        } catch (Exception e) {
            err("Full sync for target=%s FAILED: %s", model.getName(), e.getMessage());
            SynchronizationResult failed = new SynchronizationResult();
            failed.setFailed(1);
            return failed;
        }
        SynchronizationResult result = new SynchronizationResult();
        result.setAdded(counts[0]);
        result.setFailed(counts[1]);
        return result;
    }

    private SynchronizationResult runPendingSweep(KeycloakSessionFactory sessionFactory, String realmId, ComponentModel model) {
        long start = System.currentTimeMillis();
        try {
            KeycloakModelUtils.runJobInTransaction(sessionFactory, session -> {
                RealmModel realm = session.realms().getRealm(realmId);
                if (realm == null) {
                    err("Realm not found for realmId=%s during changed-users sync of target=%s", realmId, model.getName());
                    return;
                }
                session.getContext().setRealm(realm);
                ScimMembershipSync.processPendingMembershipChanges(session, realm, model.getId());
            });
            info("Changed-users sync for target=%s completed in %dms", model.getName(), System.currentTimeMillis() - start);
        } catch (Exception e) {
            err("Changed-users sync for target=%s FAILED: %s", model.getName(), e.getMessage());
            SynchronizationResult failed = new SynchronizationResult();
            failed.setFailed(1);
            return failed;
        }
        return new SynchronizationResult();
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
