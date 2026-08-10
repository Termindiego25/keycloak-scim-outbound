package es.diegosr.keycloak_scim_outbound;

import es.diegosr.keycloak_scim_outbound.http.ScimClient;
import es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.events.Details;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserProvider;

import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ScimEventListenerProviderDeleteTest {

    private static final String REALM_ID = "realm-id";
    private static final String USER_ID = "keycloak-user-id";
    private static final String SCIM_ID = "scim-user-id";

    @Test
    void adminDeleteUsesUsernameFromRepresentationForLegacyLookup() {
        Fixture fixture = fixture("username");
        when(fixture.client().findUserIdByExternalId(USER_ID)).thenReturn(Optional.empty());
        when(fixture.client().findUserIdByUserName("alice")).thenReturn(Optional.of(SCIM_ID));
        when(fixture.client().patchUser(anyString(), anyString())).thenReturn(true);

        AdminEvent event = adminDeleteEvent();
        event.setRepresentation("{\"id\":\"keycloak-user-id\",\"username\":\"alice\"}");

        fixture.provider().onEvent(event, false);

        verify(fixture.client()).findUserIdByExternalId(USER_ID);
        verify(fixture.client()).findUserIdByUserName("alice");
        verify(fixture.client(), never()).findUserIdByUserName("(unknown)");
        verify(fixture.client()).patchUser(eq(SCIM_ID), anyString());
    }

    @Test
    void selfDeleteUsesUsernameFromEventDetailsForLegacyLookup() {
        Fixture fixture = fixture("username");
        when(fixture.client().findUserIdByExternalId(USER_ID)).thenReturn(Optional.empty());
        when(fixture.client().findUserIdByUserName("alice")).thenReturn(Optional.of(SCIM_ID));
        when(fixture.client().patchUser(anyString(), anyString())).thenReturn(true);

        Event event = new Event();
        event.setRealmId(REALM_ID);
        event.setUserId(USER_ID);
        event.setType(EventType.DELETE_ACCOUNT);
        event.setDetails(Map.of(Details.USERNAME, "alice"));

        fixture.provider().onEvent(event);

        verify(fixture.client()).findUserIdByExternalId(USER_ID);
        verify(fixture.client()).findUserIdByUserName("alice");
        verify(fixture.client(), never()).findUserIdByUserName("(unknown)");
        verify(fixture.client()).patchUser(eq(SCIM_ID), anyString());
    }

    @Test
    void deleteWithEmailStrategyCanUseExternalIdWithoutAUserModel() {
        Fixture fixture = fixture("email");
        when(fixture.client().findUserIdByExternalId(USER_ID)).thenReturn(Optional.of(SCIM_ID));
        when(fixture.client().patchUser(anyString(), anyString())).thenReturn(true);

        AdminEvent event = adminDeleteEvent();
        event.setRepresentation("{\"id\":\"keycloak-user-id\",\"username\":\"alice\"}");

        fixture.provider().onEvent(event, false);

        verify(fixture.client()).findUserIdByExternalId(USER_ID);
        verify(fixture.client(), never()).findUserIdByUserName(anyString());
        verify(fixture.client()).patchUser(eq(SCIM_ID), anyString());
    }

    @Test
    void deleteWithEmailStrategyDoesNotTreatKeycloakUsernameAsScimUserName() {
        Fixture fixture = fixture("email");
        when(fixture.client().findUserIdByExternalId(USER_ID)).thenReturn(Optional.empty());

        AdminEvent event = adminDeleteEvent();
        event.setRepresentation("{\"id\":\"keycloak-user-id\",\"username\":\"alice\"}");

        fixture.provider().onEvent(event, false);

        verify(fixture.client()).findUserIdByExternalId(USER_ID);
        verify(fixture.client(), never()).findUserIdByUserName(anyString());
        verify(fixture.client(), never()).patchUser(anyString(), anyString());
        verify(fixture.client(), never()).deleteUser(anyString());
    }

    private static Fixture fixture(String userNameStrategy) {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmProvider realms = mock(RealmProvider.class);
        UserProvider users = mock(UserProvider.class);
        RealmModel realm = mock(RealmModel.class);
        ScimClient client = mock(ScimClient.class);

        ComponentModel target = new ComponentModel();
        target.setId("target-id");
        target.setName("target");
        target.setProviderId(ScimTargetProviderFactory.ID);

        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        config.putSingle(ScimTargetProviderFactory.CFG_BASE_URL, "https://target.example/scim/v2");
        config.putSingle(ScimTargetProviderFactory.CFG_TOKEN, "token");
        config.putSingle(ScimTargetProviderFactory.CFG_UNAME_STRATEGY, userNameStrategy);
        config.putSingle(ScimTargetProviderFactory.CFG_DEPROVISION, "deactivate");
        target.setConfig(config);

        when(session.realms()).thenReturn(realms);
        when(session.users()).thenReturn(users);
        when(realms.getRealm(REALM_ID)).thenReturn(realm);
        when(users.getUserById(realm, USER_ID)).thenReturn(null);
        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getName()).thenReturn("realm");
        when(realm.getComponentsStream()).thenAnswer(ignored -> Stream.of(target));

        ScimEventListenerProvider provider = new ScimEventListenerProvider(
                session, (baseUrl, token) -> client, () -> 1_000L);
        return new Fixture(provider, client);
    }

    private static AdminEvent adminDeleteEvent() {
        AdminEvent event = new AdminEvent();
        event.setRealmId(REALM_ID);
        event.setResourceType(ResourceType.USER);
        event.setOperationType(OperationType.DELETE);
        event.setResourcePath("users/" + USER_ID);
        return event;
    }

    private record Fixture(ScimEventListenerProvider provider, ScimClient client) { }
}
