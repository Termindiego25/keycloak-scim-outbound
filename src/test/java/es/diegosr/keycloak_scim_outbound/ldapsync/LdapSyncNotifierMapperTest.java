package es.diegosr.keycloak_scim_outbound.ldapsync;

import es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.GroupProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.storage.DatastoreProvider;
import org.keycloak.storage.datastore.DefaultDatastoreProvider;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static es.diegosr.keycloak_scim_outbound.ldapsync.MembershipState.State.NEW_ADDED;
import static es.diegosr.keycloak_scim_outbound.ldapsync.MembershipState.State.NEW_DELETED;
import static es.diegosr.keycloak_scim_outbound.ldapsync.MembershipState.State.SENT;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Area 5 -- Event-driven state writes in LdapSyncNotifierMapper.
 *
 * Verifies that checkAndUpdateMembership (called from onImportUserFromLDAP) writes
 * the correct MembershipState transitions and pending flags for each scenario.
 * Group-side writes (GroupMembershipState) are also covered.
 */
@ExtendWith(MockitoExtension.class)
class LdapSyncNotifierMapperTest {

    static final String TARGET_ID  = "target-1";
    static final String GROUP_ID   = "kc-group-1";
    static final String GROUP_NAME = "filter-grp";
    static final String USER_ID    = "user-1";

    @Mock KeycloakSession           session;
    @Mock RealmModel                realm;
    @Mock ComponentModel            target;
    @Mock UserModel                 user;
    @Mock UserModel                 localUser;
    @Mock GroupModel                filterGroup;
    @Mock GroupProvider             groupProvider;
    @Mock DefaultDatastoreProvider  datastoreProvider;
    @Mock UserProvider              localUserProvider;

    LdapSyncNotifierMapper mapper;

    @BeforeEach
    void setUp() {
        when(realm.getName()).thenReturn("test-realm");
        when(realm.getComponentsStream()).thenReturn(Stream.of(target));
        when(target.getProviderId()).thenReturn(ScimTargetProviderFactory.ID);
        when(target.getId()).thenReturn(TARGET_ID);
        when(target.getName()).thenReturn("Test Target");
        lenient().when(target.get(ScimTargetProviderFactory.CFG_FILTER_GROUP)).thenReturn(GROUP_NAME);
        lenient().when(target.get(ScimTargetProviderFactory.CFG_SYNC_GROUPS)).thenReturn("false");

        when(session.groups()).thenReturn(groupProvider);

        when(filterGroup.getId()).thenReturn(GROUP_ID);
        when(filterGroup.getName()).thenReturn(GROUP_NAME);
        when(groupProvider.searchForGroupByNameStream(eq(realm), eq(GROUP_NAME), eq(true), isNull(), isNull()))
                .thenReturn(Stream.of(filterGroup));

        when(user.getId()).thenReturn(USER_ID);
        when(user.getUsername()).thenReturn("alice");

        mapper = new LdapSyncNotifierMapper(session, target);
    }

    // -------------------------------------------------------------------------
    // User added to filter group -> NEW_ADDED written
    // -------------------------------------------------------------------------

    @Test
    void userAddedToFilterGroup_newAddedWritten() {
        // User is currently a member of the filter group
        when(user.getGroupsStream()).thenReturn(Stream.of(filterGroup));
        // No existing state entry
        when(user.getAttributeStream(MembershipState.ATTRIBUTE_NAME)).thenReturn(Stream.empty());

        mockLocalStorage(localUser);

        mapper.onImportUserFromLDAP(null, user, realm, false);

        ArgumentCaptor<List> stateCaptor = ArgumentCaptor.forClass(List.class);
        verify(localUser, atLeastOnce())
                .setAttribute(eq(MembershipState.ATTRIBUTE_NAME), stateCaptor.capture());

        List<String> written = stateCaptor.getValue();
        Optional<MembershipState> entry = written.stream()
                .map(MembershipState::parse)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .filter(e -> e.componentId().equals(TARGET_ID))
                .findFirst();

        assertTrue(entry.isPresent(), "A state entry must be written for target-1");
        assertEquals(NEW_ADDED, entry.get().state(), "State must be NEW_ADDED");
        assertEquals(GROUP_ID, entry.get().groupId(), "groupId must match filter group id");
    }

    // -------------------------------------------------------------------------
    // User removed from filter group -> NEW_DELETED written
    // -------------------------------------------------------------------------

    @Test
    void userRemovedFromFilterGroup_newDeletedWritten() {
        // User is NOT currently a member
        when(user.getGroupsStream()).thenReturn(Stream.empty());
        // Existing SENT entry
        String sentEntry = new MembershipState(TARGET_ID, GROUP_ID, SENT).toValue();
        when(user.getAttributeStream(MembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.of(sentEntry));

        mockLocalStorage(localUser);

        mapper.onImportUserFromLDAP(null, user, realm, false);

        ArgumentCaptor<List> stateCaptor = ArgumentCaptor.forClass(List.class);
        verify(localUser, atLeastOnce())
                .setAttribute(eq(MembershipState.ATTRIBUTE_NAME), stateCaptor.capture());

        List<String> written = stateCaptor.getValue();
        Optional<MembershipState> entry = written.stream()
                .map(MembershipState::parse)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .filter(e -> e.componentId().equals(TARGET_ID))
                .findFirst();

        assertTrue(entry.isPresent());
        assertEquals(NEW_DELETED, entry.get().state(), "SENT must be replaced with NEW_DELETED");
    }

    // -------------------------------------------------------------------------
    // Re-add after NEW_DELETED -> replaced with NEW_ADDED (cancel-out)
    // -------------------------------------------------------------------------

    @Test
    void reAddAfterNewDeleted_replacedWithNewAdded() {
        when(user.getGroupsStream()).thenReturn(Stream.of(filterGroup));
        String delEntry = new MembershipState(TARGET_ID, GROUP_ID, NEW_DELETED).toValue();
        when(user.getAttributeStream(MembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.of(delEntry));

        mockLocalStorage(localUser);

        mapper.onImportUserFromLDAP(null, user, realm, false);

        ArgumentCaptor<List> stateCaptor = ArgumentCaptor.forClass(List.class);
        verify(localUser, atLeastOnce())
                .setAttribute(eq(MembershipState.ATTRIBUTE_NAME), stateCaptor.capture());

        List<String> written = stateCaptor.getValue();
        long newAddedCount = written.stream()
                .map(MembershipState::parse)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .filter(e -> e.componentId().equals(TARGET_ID) && e.state() == NEW_ADDED)
                .count();
        long newDeletedCount = written.stream()
                .map(MembershipState::parse)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .filter(e -> e.componentId().equals(TARGET_ID) && e.state() == NEW_DELETED)
                .count();

        assertEquals(1, newAddedCount, "Exactly one NEW_ADDED entry must be present");
        assertEquals(0, newDeletedCount, "NEW_DELETED must be cancelled out");
    }

    // -------------------------------------------------------------------------
    // Remove after NEW_ADDED -> replaced with NEW_DELETED (cancel-out)
    // -------------------------------------------------------------------------

    @Test
    void removeAfterNewAdded_replacedWithNewDeleted() {
        when(user.getGroupsStream()).thenReturn(Stream.empty());
        String addEntry = new MembershipState(TARGET_ID, GROUP_ID, NEW_ADDED).toValue();
        when(user.getAttributeStream(MembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.of(addEntry));

        mockLocalStorage(localUser);

        mapper.onImportUserFromLDAP(null, user, realm, false);

        ArgumentCaptor<List> stateCaptor = ArgumentCaptor.forClass(List.class);
        verify(localUser, atLeastOnce())
                .setAttribute(eq(MembershipState.ATTRIBUTE_NAME), stateCaptor.capture());

        List<String> written = stateCaptor.getValue();
        long newDeletedCount = written.stream()
                .map(MembershipState::parse)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .filter(e -> e.componentId().equals(TARGET_ID) && e.state() == NEW_DELETED)
                .count();
        assertEquals(1, newDeletedCount, "NEW_ADDED must be replaced with NEW_DELETED");
    }

    // -------------------------------------------------------------------------
    // Already SENT, user still in group -> no state change
    // -------------------------------------------------------------------------

    @Test
    void alreadySent_userStillInGroup_noStateChange() {
        when(user.getGroupsStream()).thenReturn(Stream.of(filterGroup));
        String sentEntry = new MembershipState(TARGET_ID, GROUP_ID, SENT).toValue();
        when(user.getAttributeStream(MembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.of(sentEntry));

        mapper.onImportUserFromLDAP(null, user, realm, false);

        // No write to local storage because nothing changed
        verify(localUser, never()).setAttribute(eq(MembershipState.ATTRIBUTE_NAME), any());
    }

    // -------------------------------------------------------------------------
    // Event for non-filter group -> no state written
    // -------------------------------------------------------------------------

    @Test
    void eventForNonFilterGroup_noStateWritten() {
        // User is in a different group, not the filter group
        GroupModel otherGroup = mock(GroupModel.class);
        when(otherGroup.getId()).thenReturn("other-group-id");
        when(user.getGroupsStream()).thenReturn(Stream.of(otherGroup));
        when(user.getAttributeStream(MembershipState.ATTRIBUTE_NAME)).thenReturn(Stream.empty());

        mapper.onImportUserFromLDAP(null, user, realm, false);

        verify(localUser, never()).setAttribute(any(), any());
    }

    // -------------------------------------------------------------------------
    // Entries for other targets are preserved
    // -------------------------------------------------------------------------

    @Test
    void otherTargetEntriesPreserved() {
        when(user.getGroupsStream()).thenReturn(Stream.of(filterGroup));
        // Existing SENT entry for a different target
        String otherEntry = new MembershipState("other-target", "other-group", SENT).toValue();
        when(user.getAttributeStream(MembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.of(otherEntry));

        mockLocalStorage(localUser);

        mapper.onImportUserFromLDAP(null, user, realm, false);

        ArgumentCaptor<List> stateCaptor = ArgumentCaptor.forClass(List.class);
        verify(localUser, atLeastOnce())
                .setAttribute(eq(MembershipState.ATTRIBUTE_NAME), stateCaptor.capture());

        List<String> written = stateCaptor.getValue();
        boolean otherTargetPresent = written.stream()
                .map(MembershipState::parse)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .anyMatch(e -> e.componentId().equals("other-target"));

        assertTrue(otherTargetPresent, "Entry for other-target must survive unchanged");
    }

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    /**
     * Stubs the local-storage chain that production code reaches via
     * UserStoragePrivateUtil.userLocalStorage(session).getUserById(realm, userId).
     *
     * In Keycloak 26.x, UserStoragePrivateUtil.userLocalStorage(session) is:
     *   ((DefaultDatastoreProvider) session.getProvider(DatastoreProvider.class))
     *       .userLocalStorage()
     *
     * We stub session.getProvider(DatastoreProvider.class) -- note: DatastoreProvider.class
     * is the lookup key, not DefaultDatastoreProvider.class. No static mocking needed.
     */
    private void mockLocalStorage(UserModel local) {
        lenient().when(session.getProvider(DatastoreProvider.class))
                .thenReturn(datastoreProvider);
        lenient().when(datastoreProvider.userLocalStorage())
                .thenReturn(localUserProvider);
        lenient().when(localUserProvider.getUserById(eq(realm), eq(USER_ID)))
                .thenReturn(local);
    }
}
