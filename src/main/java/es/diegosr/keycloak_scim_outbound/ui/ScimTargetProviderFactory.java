package es.diegosr.keycloak_scim_outbound.ui;

import es.diegosr.keycloak_scim_outbound.ldapsync.ScimGroupSync;
import es.diegosr.keycloak_scim_outbound.ldapsync.ScimMembershipSync;
import es.diegosr.keycloak_scim_outbound.util.ScimMapper;
import org.jboss.logging.Logger;

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
 * UI-configurable provider (shows up under Realm -> User Federation -> Add provider).
 * Holds SCIM target configuration; the event listener reads it to push SCIM operations.
 *
 * Implements ImportSynchronization so that clicking "Synchronize all users" /
 * "Synchronize changed users" in the admin console triggers a sweep for this target only.
 *
 * Sync execution order (critical invariant):
 *   Step 1 -- User sync (always before group sync)
 *   Step 2 -- Group sync (only if CFG_SYNC_GROUPS = true)
 *   Step 3 -- Group deprovision sweep (only if CFG_SYNC_GROUPS = true)
 */
public class ScimTargetProviderFactory
        implements UserStorageProviderFactory<ScimTargetProvider>, ImportSynchronization {

    private static final Logger LOG = Logger.getLogger(ScimTargetProviderFactory.class);

    /** Stable provider id. Keep in sync with the listener lookup. */
    public static final String ID = "keycloak-scim-outbound";

    // =========================================================================
    // Config keys
    // =========================================================================

    public static final String CFG_BASE_URL    = "baseUrl";
    public static final String CFG_TOKEN       = "token";
    public static final String CFG_FILTER_GROUP = "filterGroup";

    /** How to build SCIM userName: username | email | attribute */
    public static final String CFG_UNAME_STRATEGY = "userNameStrategy";
    /** Attribute name when strategy=attribute */
    public static final String CFG_UNAME_ATTR     = "userNameAttribute";

    /** Deprovisioning behavior: deactivate | delete */
    public static final String CFG_DEPROVISION = "deprovisionAction";

    /** Enable SCIM /Groups sync. */
    public static final String CFG_SYNC_GROUPS = "syncGroups";

    /**
     * Comma-separated list of exact group names to sync (default mode).
     * When CFG_SYNC_GROUPS_FILTER_REGEX is true, treated as a Java regex instead.
     * Empty: falls back to CFG_FILTER_GROUP (single exact match).
     */
    public static final String CFG_SYNC_GROUPS_FILTER = "syncGroupsFilter";

    /**
     * When true, CFG_SYNC_GROUPS_FILTER is interpreted as a Java regex.
     * When false (default), it is interpreted as a comma-separated list of exact names.
     */
    public static final String CFG_SYNC_GROUPS_FILTER_REGEX = "syncGroupsFilterRegex";

    /** LDAP Users Provisioning Mode: Delta | Full */
    public static final String CFG_LDAP_USER_PROV_MODE = "ldapUserProvMode";

    /**
     * LDAP Groups Provisioning Mode:
     *   "Delta (add members)" | "Delta (add and remove members)" | "Full"
     */
    public static final String CFG_LDAP_GROUP_PROV_MODE = "ldapGroupProvMode";

    /**
     * SCIM PATCH remove form for group membership changes.
     * "RFC 7644 path filter" (default) or "Non-RFC value array".
     */
    public static final String CFG_GROUP_MEMBER_REMOVE_FORM = "groupMemberRemoveForm";

    /**
     * SCIM ID lookup strategy for /Users and /Groups resolution.
     * "externalId first" (default) or "name only".
     */
    public static final String CFG_LOOKUP_STRATEGY = "lookupStrategy";

    public static final String LOOKUP_STRATEGY_EXTERNAL_ID_FIRST = "externalId first";
    public static final String LOOKUP_STRATEGY_NAME_ONLY         = "name only";

    // =========================================================================
    // Config property definitions
    // =========================================================================

    private static ProviderConfigProperty str(String name, String label, String help, boolean required) {
        ProviderConfigProperty p = new ProviderConfigProperty();
        p.setType(ProviderConfigProperty.STRING_TYPE);
        p.setName(name); p.setLabel(label); p.setHelpText(help); p.setRequired(required);
        return p;
    }

    private static ProviderConfigProperty pwd(String name, String label, String help) {
        ProviderConfigProperty p = new ProviderConfigProperty();
        p.setType(ProviderConfigProperty.PASSWORD);
        p.setName(name); p.setLabel(label); p.setHelpText(help); p.setSecret(true);
        return p;
    }

    private static ProviderConfigProperty bool(String name, String label, String help) {
        ProviderConfigProperty p = new ProviderConfigProperty();
        p.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        p.setName(name); p.setLabel(label); p.setHelpText(help);
        return p;
    }

    private static ProviderConfigProperty list(String name, String label, String help,
                                               List<String> options, String def, boolean required) {
        ProviderConfigProperty p = new ProviderConfigProperty();
        p.setType(ProviderConfigProperty.LIST_TYPE);
        p.setName(name); p.setLabel(label); p.setHelpText(help);
        p.setOptions(options); p.setDefaultValue(def); p.setRequired(required);
        return p;
    }

    private static final List<ProviderConfigProperty> PROPS = List.of(
        str(CFG_BASE_URL, "SCIM Base URL",
            "SCIM endpoint base URL (e.g. https://app.example.com/scim/v2).", true),
        pwd(CFG_TOKEN, "SCIM Token",
            "Bearer token used to authenticate against the SCIM endpoint."),
        str(CFG_FILTER_GROUP, "Filter Group (optional)",
            "If set, only users in this Keycloak group are provisioned.", false),

        list(CFG_UNAME_STRATEGY, "UserName Strategy",
            "How to build SCIM 'userName': 'username' (Keycloak username), 'email', "
            + "or a custom user attribute.",
            List.of("username", "email", "attribute"), "username", true),

        str(CFG_UNAME_ATTR, "UserName Attribute",
            "User attribute name when userNameStrategy=attribute (e.g. scim_username).", false),

        list(CFG_DEPROVISION, "Deprovision Action",
            "Behavior when a user is deleted or removed from the filter group: "
            + "'deactivate' (PATCH active=false, default) or 'delete' (DELETE /Users/{id}).",
            List.of("deactivate", "delete"), "deactivate", true),

        list(CFG_LOOKUP_STRATEGY, "Lookup Strategy",
            "SCIM ID lookup strategy for /Users and /Groups. "
            + "'externalId first': query by externalId filter first, fall back to "
            + "userName/displayName on miss or ambiguous result. "
            + "'name only': skip externalId lookup; go straight to userName/displayName. "
            + "Use 'name only' when the SCIM server ignores the externalId filter.",
            List.of(LOOKUP_STRATEGY_EXTERNAL_ID_FIRST, LOOKUP_STRATEGY_NAME_ONLY),
            LOOKUP_STRATEGY_EXTERNAL_ID_FIRST, true),

        bool(CFG_SYNC_GROUPS, "Sync Groups",
            "Enable SCIM /Groups sync. When enabled, group create/update/delete and "
            + "membership changes are pushed to SCIM /Groups."),

        str(CFG_SYNC_GROUPS_FILTER, "Sync Groups Filter",
            "Comma-separated list of exact group names to sync via the LDAP sync path "
            + "(e.g. admins,developers,team-alpha). "
            + "Enable 'Use Regex for Group Filter' to treat this as a Java regex instead. "
            + "Leave empty to scope to Filter Group only. "
            + "Only used when Sync Groups is enabled.", false),

        bool(CFG_SYNC_GROUPS_FILTER_REGEX, "Use Regex for Group Filter",
            "When enabled, Sync Groups Filter is interpreted as a Java regular expression "
            + "instead of a comma-separated list of exact names."),

        list(CFG_LDAP_USER_PROV_MODE, "LDAP Users Provisioning Mode",
            "'Delta' flushes only pending changes (default). "
            + "'Full' re-provisions all filter-group members on every sync.",
            List.of("Delta", "Full"), "Delta", true),

        list(CFG_LDAP_GROUP_PROV_MODE, "LDAP Groups Provisioning Mode",
            "'Delta (add members)' flushes pending adds only (default). "
            + "'Delta (add and remove members)' flushes adds and removes then runs a cross-check. "
            + "'Full' sends a complete member-list replace for all in-scope groups.",
            List.of(ScimGroupSync.MODE_DELTA_ONLY,
                    ScimGroupSync.MODE_DELTA_DEPROVISION,
                    ScimGroupSync.MODE_FULL),
            ScimGroupSync.MODE_DELTA_ONLY, true),

        list(CFG_GROUP_MEMBER_REMOVE_FORM, "Group Member Remove Form",
            "'RFC 7644 path filter' (default): members[value eq \"<id>\"] -- spec-compliant. "
            + "'Non-RFC value array': includes a value field on removes for servers that require it.",
            List.of(ScimMapper.REMOVE_FORM_RFC_PATH_FILTER,
                    ScimMapper.REMOVE_FORM_NON_RFC_VALUE_ARRAY),
            ScimMapper.REMOVE_FORM_RFC_PATH_FILTER, true)
    );

    @Override
    public List<ProviderConfigProperty> getConfigProperties() { return PROPS; }

    @Override
    public ScimTargetProvider create(KeycloakSession session, ComponentModel model) {
        return new ScimTargetProvider(session, model);
    }

    @Override
    public String getId() { return ID; }

    public String getHelpText() {
        return "Push users to an external SCIM endpoint (Passbolt, Nextcloud, ...) "
               + "with optional group filtering.";
    }

    @Override public void init(org.keycloak.Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}

    // =========================================================================
    // Validation
    // =========================================================================

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
                require(model, CFG_UNAME_ATTR,
                        "When userNameStrategy=attribute, 'userNameAttribute' is required");
                break;
            default:
                throw new ComponentValidationException(
                        "Invalid userNameStrategy. Use 'username', 'email', or 'attribute'.");
        }

        String deprovision = get(model, CFG_DEPROVISION, "deactivate");
        if (!"deactivate".equals(deprovision) && !"delete".equals(deprovision)) {
            throw new ComponentValidationException(
                    "Invalid deprovisionAction. Use 'deactivate' or 'delete'.");
        }

        // When regex mode is enabled, validate the pattern at save time.
        boolean useRegex = "true".equalsIgnoreCase(get(model, CFG_SYNC_GROUPS_FILTER_REGEX, "false"));
        String groupsFilter = get(model, CFG_SYNC_GROUPS_FILTER, null);
        if (useRegex && groupsFilter != null && !groupsFilter.isBlank()) {
            try {
                java.util.regex.Pattern.compile(groupsFilter);
            } catch (java.util.regex.PatternSyntaxException e) {
                throw new ComponentValidationException(
                        "Sync Groups Filter is not a valid Java regex: " + e.getMessage());
            }
        }
    }

    // =========================================================================
    // ImportSynchronization
    // =========================================================================

    @Override
    public SynchronizationResult sync(KeycloakSessionFactory sessionFactory,
                                       String realmId, UserStorageProviderModel model) {
        LOG.infof("Manual 'Synchronize all users' triggered for target=%s (componentId=%s) realm=%s",
                model.getName(), model.getId(), realmId);
        return runSweep(sessionFactory, realmId, model, true);
    }

    @Override
    public SynchronizationResult syncSince(Date lastSync, KeycloakSessionFactory sessionFactory,
                                            String realmId, UserStorageProviderModel model) {
        LOG.infof("Manual 'Synchronize changed users' triggered for target=%s (componentId=%s) "
                + "realm=%s lastSync=%s", model.getName(), model.getId(), realmId, lastSync);
        return runSweep(sessionFactory, realmId, model, false);
    }

    /**
     * Runs user sync, then group sync, then group deprovision sweep.
     *
     * @param fullSync true when called from sync() (Synchronize all); false for syncSince().
     *                 When true, always uses full-sync mode for both users and groups.
     */
    private SynchronizationResult runSweep(KeycloakSessionFactory sessionFactory, String realmId,
                                            ComponentModel model, boolean fullSync) {
        long start = System.currentTimeMillis();
        try {
            KeycloakModelUtils.runJobInTransaction(sessionFactory, session -> {
                RealmModel realm = session.realms().getRealm(realmId);
                if (realm == null) {
                    LOG.errorf("Realm not found for realmId=%s during sync of target=%s",
                            realmId, model.getName());
                    return;
                }
                session.getContext().setRealm(realm);

                // Step 1: User sync
                if (fullSync || "Full".equals(get(model, CFG_LDAP_USER_PROV_MODE, "Delta"))) {
                    ScimMembershipSync.processFullUserSync(session, realm, model.getId());
                } else {
                    ScimMembershipSync.processPendingMembershipChanges(session, realm, model.getId());
                }

                // Step 2: Group sync
                if ("true".equalsIgnoreCase(get(model, CFG_SYNC_GROUPS, "false"))) {
                    String groupMode = get(model, CFG_LDAP_GROUP_PROV_MODE, ScimGroupSync.MODE_DELTA_ONLY);
                    if (fullSync || ScimGroupSync.MODE_FULL.equals(groupMode)) {
                        ScimGroupSync.processFullGroupSync(session, realm, model.getId());
                    } else {
                        ScimGroupSync.processPendingGroupMembershipChanges(
                                session, realm, model.getId(), groupMode);
                    }
                }

                // Step 3: Group deprovision sweep
                if ("true".equalsIgnoreCase(get(model, CFG_SYNC_GROUPS, "false"))) {
                    ScimGroupSync.deprovisionOutOfScopeGroups(session, realm, model.getId());
                }
            });
            LOG.infof("Manual sync for target=%s completed in %dms",
                    model.getName(), System.currentTimeMillis() - start);
        } catch (Exception e) {
            LOG.errorf("Manual sync for target=%s FAILED: %s", model.getName(), e.getMessage());
            SynchronizationResult failed = new SynchronizationResult();
            failed.setFailed(1);
            return failed;
        }
        return new SynchronizationResult();
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private static void require(ComponentModel model, String key, String msg)
            throws ComponentValidationException {
        String v = get(model, key, null);
        if (v == null || v.isBlank()) throw new ComponentValidationException(msg);
    }

    public static String get(ComponentModel m, String key, String def) {
        String v = m.getConfig().getFirst(key);
        return v != null ? v : def;
    }
}
