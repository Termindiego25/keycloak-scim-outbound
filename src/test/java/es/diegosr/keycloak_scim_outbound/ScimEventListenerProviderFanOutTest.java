package es.diegosr.keycloak_scim_outbound;

import es.diegosr.keycloak_scim_outbound.http.ScimClient;
import es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.GroupModel;
import org.keycloak.models.GroupProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ScimEventListenerProviderFanOutTest {

    private static final String REALM_ID = "realm-id";
    private static final String USER_ID = "user-id";
    private static final String GROUP_ID = "group-id";

    @Test
    void membershipEventReachesEveryTargetAndDuplicateIsDebouncedPerTarget() {
        Fixture fixture = fixture();
        when(fixture.targetA().findGroupIdByExternalId(GROUP_ID))
                .thenReturn(Optional.of("scim-group-a"));
        when(fixture.targetB().findGroupIdByExternalId(GROUP_ID))
                .thenReturn(Optional.of("scim-group-b"));
        when(fixture.targetA().findUserIdByExternalId(USER_ID))
                .thenReturn(Optional.of("scim-user-a"));
        when(fixture.targetB().findUserIdByExternalId(USER_ID))
                .thenReturn(Optional.of("scim-user-b"));
        when(fixture.targetA().patchGroup(anyString(), anyString())).thenReturn(true);
        when(fixture.targetB().patchGroup(anyString(), anyString())).thenReturn(true);

        AdminEvent event = event(
                ResourceType.GROUP_MEMBERSHIP,
                OperationType.CREATE,
                "users/" + USER_ID + "/groups/" + GROUP_ID);

        fixture.provider().onEvent(event, false);
        fixture.provider().onEvent(event, false);

        verify(fixture.targetA(), times(1)).patchGroup(eq("scim-group-a"), anyString());
        verify(fixture.targetB(), times(1)).patchGroup(eq("scim-group-b"), anyString());
    }

    @Test
    void userEventReachesEveryTargetBeforeGlobalDuplicateIsDebounced() {
        Fixture fixture = fixture();
        when(fixture.targetA().findUserIdByExternalId(USER_ID))
                .thenReturn(Optional.of("scim-user-a"));
        when(fixture.targetB().findUserIdByExternalId(USER_ID))
                .thenReturn(Optional.of("scim-user-b"));
        when(fixture.targetA().patchUser(anyString(), anyString())).thenReturn(true);
        when(fixture.targetB().patchUser(anyString(), anyString())).thenReturn(true);

        AdminEvent event = event(ResourceType.USER, OperationType.UPDATE, "users/" + USER_ID);

        fixture.provider().onEvent(event, false);
        fixture.provider().onEvent(event, false);

        verify(fixture.targetA(), times(1)).patchUser(eq("scim-user-a"), anyString());
        verify(fixture.targetB(), times(1)).patchUser(eq("scim-user-b"), anyString());
    }

    @Test
    void groupCrudEventReachesEveryTarget() {
        Fixture fixture = fixture();
        when(fixture.targetA().createGroup(anyString())).thenReturn(true);
        when(fixture.targetB().createGroup(anyString())).thenReturn(true);

        AdminEvent event = event(ResourceType.GROUP, OperationType.CREATE, "groups/" + GROUP_ID);

        fixture.provider().onEvent(event, false);

        verify(fixture.targetA(), times(1)).createGroup(anyString());
        verify(fixture.targetB(), times(1)).createGroup(anyString());
    }

    private static Fixture fixture() {
        KeycloakSession session = mock(KeycloakSession.class);
        RealmProvider realms = mock(RealmProvider.class);
        UserProvider users = mock(UserProvider.class);
        GroupProvider groups = mock(GroupProvider.class);
        RealmModel realm = mock(RealmModel.class);
        UserModel user = mock(UserModel.class);
        GroupModel group = mock(GroupModel.class);

        ComponentModel componentA = target("target-a", "https://target-a.example/scim/v2");
        ComponentModel componentB = target("target-b", "https://target-b.example/scim/v2");

        when(session.realms()).thenReturn(realms);
        when(session.users()).thenReturn(users);
        when(session.groups()).thenReturn(groups);
        when(realms.getRealm(REALM_ID)).thenReturn(realm);
        when(users.getUserById(realm, USER_ID)).thenReturn(user);
        when(groups.getGroupById(realm, GROUP_ID)).thenReturn(group);
        when(realm.getId()).thenReturn(REALM_ID);
        when(realm.getName()).thenReturn("realm");
        when(realm.getComponentsStream()).thenAnswer(ignored -> Stream.of(componentA, componentB));
        when(user.getId()).thenReturn(USER_ID);
        when(user.getUsername()).thenReturn("alice");
        when(user.getFirstName()).thenReturn("Alice");
        when(user.getLastName()).thenReturn("Example");
        when(user.getEmail()).thenReturn("alice@example.com");
        when(user.isEnabled()).thenReturn(true);
        when(group.getName()).thenReturn("team");

        ScimClient targetA = mock(ScimClient.class);
        ScimClient targetB = mock(ScimClient.class);
        Map<String, ScimClient> clients = Map.of(
                "https://target-a.example/scim/v2", targetA,
                "https://target-b.example/scim/v2", targetB);

        ScimEventListenerProvider provider = new ScimEventListenerProvider(
                session, (baseUrl, token) -> clients.get(baseUrl), () -> 1_000L);
        return new Fixture(provider, targetA, targetB);
    }

    private static ComponentModel target(String id, String baseUrl) {
        ComponentModel target = new ComponentModel();
        target.setId(id);
        target.setName(id);
        target.setProviderId(ScimTargetProviderFactory.ID);

        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        config.putSingle(ScimTargetProviderFactory.CFG_BASE_URL, baseUrl);
        config.putSingle(ScimTargetProviderFactory.CFG_TOKEN, "token");
        config.putSingle(ScimTargetProviderFactory.CFG_SYNC_GROUPS, "true");
        target.setConfig(config);
        return target;
    }

    private static AdminEvent event(ResourceType resourceType, OperationType operation, String path) {
        AdminEvent event = new AdminEvent();
        event.setRealmId(REALM_ID);
        event.setResourceType(resourceType);
        event.setOperationType(operation);
        event.setResourcePath(path);
        return event;
    }

    private record Fixture(ScimEventListenerProvider provider, ScimClient targetA, ScimClient targetB) { }
}
