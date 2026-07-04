package es.diegosr.keycloak_scim_outbound;

import es.diegosr.keycloak_scim_outbound.ldapsync.ScimMembershipSync;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.timer.TimerProvider;

public class ScimEventListenerProviderFactory implements EventListenerProviderFactory {

    private static final String LOG_TAG = "[keycloak-scim-outbound/TIMER]";

    /** How often to sweep for pending LDAP-driven membership changes. */
    private static final long INTERVAL_MS = 5 * 60 * 1000L; // 5 minutes

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new ScimEventListenerProvider(session);
    }

    @Override public void init(Config.Scope config) { }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        TimerProvider timer = KeycloakModelUtils.runJobInTransactionWithResult(factory,
                session -> session.getProvider(TimerProvider.class));

        if (timer == null) {
            err("TimerProvider not available -- periodic LDAP membership sync sweep will NOT run. "
                    + "Manual 'Synchronize' on the SCIM target will still work.");
            return;
        }

        info("Registering periodic LDAP membership sync sweep, interval=%dms", INTERVAL_MS);

        timer.schedule(() -> {
            debug("Timer tick: starting sweep across all realms.");
            long tickStart = System.currentTimeMillis();
            KeycloakModelUtils.runJobInTransaction(factory, session ->
                    session.realms().getRealmsStream().forEach(realm ->
                            ScimMembershipSync.processPendingMembershipChanges(session, realm, null)));
            debug("Timer tick: sweep finished in %dms.", System.currentTimeMillis() - tickStart);
        }, INTERVAL_MS, "scim-outbound-ldap-membership-sweep");
    }

    @Override public void close() { }

    @Override
    public String getId() {
        return "keycloak-scim-outbound";
    }

    /* ===== logging ===== */

    private static String now() {
        return java.time.OffsetDateTime.now().toString();
    }

    private static void debug(String fmt, Object... args) {
        System.out.printf("%s %s DEBUG %s%n", now(), LOG_TAG, String.format(fmt, args));
    }

    private static void info(String fmt, Object... args) {
        System.out.printf("%s %s INFO  %s%n", now(), LOG_TAG, String.format(fmt, args));
    }

    private static void err(String fmt, Object... args) {
        System.err.printf("%s %s ERROR %s%n", now(), LOG_TAG, String.format(fmt, args));
    }
}
