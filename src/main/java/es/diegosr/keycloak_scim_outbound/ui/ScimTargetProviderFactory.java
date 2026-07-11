package es.diegosr.keycloak_scim_outbound.ui;

import es.diegosr.keycloak_scim_outbound.ldapsync.ScimGroupSync;
import es.diegosr.keycloak_scim_outbound.ldapsync.ScimMembershipSync;
import es.diegosr.keycloak_scim_outbound.util.ScimMapper;

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
 * an immediate sweep of pending LDAP-driven membership changes for THIS target only.
 *
 * Sync execution order (critical invariant):
 *   Step 1 -- User sync (always before group sync, so SCIM user IDs exist by the time
 *              group sync resolves member IDs)
 *   Step 2 -- Group sync (only if CFG_SYNC_GROUPS = true)
 *
 * For each step, the provisioning mode (Delta or Full) is controlled by:
 *   CFG_LDAP_USER_PROV_MODE  -- "Delta" (default) or "Full" for /Users
 *   CFG_LDAP_GROUP_PROV_MODE -- "Delta (add members)" (default),
 *                                "Delta (add and remove members)", or "Full" for /Groups
 * sync() (Synchronize all) always runs full sync regardless of these settings.
 * syncSince() (Synchronize changed users) uses the configured mode.
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

    /** Enable SCIM /Groups sync. Disabled by default to avoid breaking existing deployments. */
    public static final String CFG_SYNC_GROUPS        = "syncGroups";

    /**
     * Optional Java regex pattern for groups to sync via the LDAP sync path.
     * When blank: only the group named by CFG_FILTER_GROUP is in scope.
     * When set: any group whose name matches this regex is in scope.
     * Only meaningful when CFG_SYNC_GROUPS is true.
     */
    public static final String CFG_SYNC_GROUPS_FILTER = "syncGroupsFilter";

    /**
     * LDAP Users Provisioning Mode for syncSince() (Synchronize changed users).
     * "Delta" (default): flush only pending entries.
     * "Full": re-provision all CFG_FILTER_GROUP members on every sync.
     */
    public static final String CFG_LDAP_USER_PROV_MODE = "ldapUserProvMode";

    /**
     * LDAP Groups Provisioning Mode for syncSince() (Synchronize changed users).
     * "Delta (add members)" (default): flush NEW_ADDED entries only; no cross-check.
     * "Delta (add and remove members)": flush NEW_ADDED + NEW_DELETED; run cross-check.
     * "Full": PATCH replace the full member list for all in-scope groups on every sync.
     */
    public static final String CFG_LDAP_GROUP_PROV_MODE = "ldapGroupProvMode";

    /**
     * SCIM PATCH remove form for group membership changes.
     * Controls the payload shape used when removing a single member from a SCIM group.
     * Read directly by ScimGroupSync from the ComponentModel at each call site.
     *
     * "RFC 7644 path filter" (default, ScimMapper.REMOVE_FORM_RFC_PATH_FILTER):
     *   {"op":"remove","path":"members[value eq \"<id>\"]"}
     *   Spec-compliant per RFC 7644 s3.5.2. Some servers reject this without a value field.
     *
     * "Non-RFC value array" (ScimMapper.REMOVE_FORM_NON_RFC_VALUE_ARRAY):
     *   {"op":"remove","path":"members","value":[{"value":"<id>"}]}
     *   Not mandated by RFC 7644 for removes, but required by servers that validate
     *   the presence of a value field on every operation.
     */
    public static final String CFG_GROUP_MEMBER_REMOVE_FORM = "groupMemberRemoveForm";

    /**
     * ID lookup strategy controlling how SCIM entity IDs are resolved for both
     * /Users and /Groups. A single key governs both user and group resolution.
     *
     * "externalId first" (default): query SCIM by externalId filter first.
     *   If exactly one result is returned, use it. If zero or more than one result
     *   is returned, fall back to userName (for users) or displayName (for groups).
     *
     * "name only": skip the externalId HTTP call entirely. Go straight to userName
     *   (for /Users) or displayName (for /Groups). Use this when the SCIM server
     *   ignores the externalId filter and returns the full user/group list regardless
     *   -- avoids a wasted HTTP round trip per resolved entity.
     */
    public static final String CFG_LOOKUP_STRATEGY = "lookupStrategy";

    /** Strategy value constants -- used by ScimGroupSync and ScimMembershipSync. */
    public static final String LOOKUP_STRATEGY_EXTERNAL_ID_FIRST = "externalId first";
    public static final String LOOKUP_STRATEGY_NAME_ONLY         = "name only";

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
            + "'deactivate' (PATCH active=false, default) or 'delete' (DELETE /Users/{id}).",
            CFG_DEPROVISION, List.of("deactivate","delete"), "deactivate", true),

        list("SCIM ID lookup strategy for both /Users and /Groups resolution. "
            + "'externalId first' (default): query by externalId filter first, fall back to "
            + "userName/displayName on miss or ambiguous result. "
            + "'name only': skip the externalId HTTP call entirely and go straight to "
            + "userName (users) or displayName (groups). "
            + "Use 'name only' when the SCIM server ignores the externalId filter.",
            CFG_LOOKUP_STRATEGY,
            List.of(LOOKUP_STRATEGY_EXTERNAL_ID_FIRST, LOOKUP_STRATEGY_NAME_ONLY),
            LOOKUP_STRATEGY_EXTERNAL_ID_FIRST, true),

        prop(ProviderConfigProperty.BOOLEAN_TYPE, CFG_SYNC_GROUPS,
            "Enable SCIM /Groups sync. When true, group create/update/delete and membership changes "
            + "are pushed to SCIM /Groups. Disabled by default.", false, "Sync Groups"),

        prop(ProviderConfigProperty.STRING_TYPE, CFG_SYNC_GROUPS_FILTER,
            "Java regex pattern for group names to sync via the LDAP sync path "
            + "(e.g. 'admins|developers|team-.*'). Leave empty to scope to Filter Group only. "
            + "Only used when Sync Groups is enabled.",
            false, "Sync Groups Filter (regex)"),

        list("LDAP Users Provisioning Mode for 'Synchronize changed users': "
            + "'Delta' flushes only pending changes (default); 'Full' re-provisions all filter-group members.",
            CFG_LDAP_USER_PROV_MODE, List.of("Delta","Full"), "Delta", true),

        list("LDAP Groups Provisioning Mode for 'Synchronize changed users': "
            + "'Delta (add members)' flushes pending adds only (default); "
            + "'Delta (add and remove members)' flushes adds and removes then runs a cross-check; "
            + "'Full' sends a complete member-list replace for all in-scope groups.",
            CFG_LDAP_GROUP_PROV_MODE,
            List.of(ScimGroupSync.MODE_DELTA_ONLY, ScimGroupSync.MODE_DELTA_DEPROVISION, ScimGroupSync.MODE_FULL),
            ScimGroupSync.MODE_DELTA_ONLY, true),

        list("SCIM PATCH remove form for group membership changes. "
            + "'RFC 7644 path filter' uses the spec-compliant path-filter form "
            + "(members[value eq \"<id>\"]). "
            + "'Non-RFC value array' includes a value field on removes "
            + "({\"value\":[{\"value\":\"<id>\"}]}) for servers that require it.",
            CFG_GROUP_MEMBER_REMOVE_FORM,
            List.of(ScimMapper.REMOVE_FORM_RFC_PATH_FILTER, ScimMapper.REMOVE_FORM_NON_RFC_VALUE_ARRAY),
            ScimMapper.REMOVE_FORM_RFC_PATH_FILTER, true)
    );

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return PROPS;
    }

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

        // CFG_SYNC_GROUPS_FILTER is now a Java regex -- no per-group name validation possible.
        // Regex syntax errors will cause java.util.regex.PatternSyntaxException at runtime;
        // we do a compile-check here to catch obvious mistakes early.
        String groupsFilter = get(model, CFG_SYNC_GROUPS_FILTER, null);
        if (groupsFilter != null && !groupsFilter.isBlank()) {
            try {
                java.util.regex.Pattern.compile(groupsFilter);
            } catch (java.util.regex.PatternSyntaxException e) {
                throw new ComponentValidationException(
                        "Sync Groups Filter is not a valid Java regex: " + e.getMessage());
            }
        }
    }

    /* ===== ImportSynchronization: triggered by the "Synchronize" buttons in the admin console =====
     * NOTE: Keycloak's ImportSynchronization interface takes UserStorageProviderModel (not the
     * plain ComponentModel) as the last parameter -- see org.keycloak.storage.user.ImportSynchronization
     * in keycloak-server-spi-private for the exact signature. */

    @Override
    public SynchronizationResult sync(KeycloakSessionFactory sessionFactory, String realmId, UserStorageProviderModel model) {
        info("Manual 'Synchronize all users' triggered for target=%s (componentId=%s) realm=%s",
                model.getName(), model.getId(), realmId);
        // Full sync regardless of configured mode
        return runSweep(sessionFactory, realmId, model, true);
    }

    @Override
    public SynchronizationResult syncSince(Date lastSync, KeycloakSessionFactory sessionFactory, String realmId, UserStorageProviderModel model) {
        info("Manual 'Synchronize changed users' triggered for target=%s (componentId=%s) realm=%s lastSync=%s",
                model.getName(), model.getId(), realmId, lastSync);
        return runSweep(sessionFactory, realmId, model, false);
    }

    /**
     * Runs the user sync sweep followed by (optionally) the group sync sweep.
     *
     * @param fullSync true when called from sync() (Synchronize all); false for syncSince()
     *                 (Synchronize changed users). When true, always uses full-sync mode for
     *                 both users and groups regardless of the configured provisioning mode keys.
     */
    private SynchronizationResult runSweep(KeycloakSessionFactory sessionFactory, String realmId,
                                            ComponentModel model, boolean fullSync) {
        long start = System.currentTimeMillis();
        try {
            KeycloakModelUtils.runJobInTransaction(sessionFactory, session -> {
                RealmModel realm = session.realms().getRealm(realmId);
                if (realm == null) {
                    err("Realm not found for realmId=%s during manual sync of target=%s", realmId, model.getName());
                    return;
                }
                // The session created by runJobInTransaction has no realm bound to its context yet.
                // Downstream code (e.g. UserModel#setAttribute, group lookups) relies on
                // session.getContext().getRealm() being set, so bind it explicitly before use.
                session.getContext().setRealm(realm);

                // ---- Step 1: User sync (always before group sync) ----
                if (fullSync || "Full".equals(get(model, CFG_LDAP_USER_PROV_MODE, "Delta"))) {
                    ScimMembershipSync.processFullUserSync(session, realm, model.getId());
                } else {
                    ScimMembershipSync.processPendingMembershipChanges(session, realm, model.getId());
                }

                // ---- Step 2: Group sync (only if CFG_SYNC_GROUPS = true) ----
                if ("true".equalsIgnoreCase(get(model, CFG_SYNC_GROUPS, "false"))) {
                    String groupMode = get(model, CFG_LDAP_GROUP_PROV_MODE, ScimGroupSync.MODE_DELTA_ONLY);
                    if (fullSync || ScimGroupSync.MODE_FULL.equals(groupMode)) {
                        ScimGroupSync.processFullGroupSync(session, realm, model.getId());
                    } else {
                        // Delta (add members) or Delta (add and remove members).
                        // ScimGroupSync reads CFG_GROUP_MEMBER_REMOVE_FORM and CFG_LOOKUP_STRATEGY
                        // directly from the ComponentModel (target) at each call site.
                        ScimGroupSync.processPendingGroupMembershipChanges(
                                session, realm, model.getId(), groupMode);
                    }
                }
            });
            info("Manual sync for target=%s completed in %dms", model.getName(), System.currentTimeMillis() - start);
        } catch (Exception e) {
            err("Manual sync for target=%s FAILED: %s", model.getName(), e.getMessage());
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
