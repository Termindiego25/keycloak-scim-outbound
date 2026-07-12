package es.diegosr.keycloak_scim_outbound.ldapsync;

import es.diegosr.keycloak_scim_outbound.http.ScimClient;
import es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory;
import org.junit.jupiter.api.AfterEach;
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
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static es.diegosr.keycloak_scim_outbound.ldapsync.GroupMembershipState.State.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Area 2 -- group delta and full sync state transitions.
 * Area 3 -- partial lookup failure (resolution safety).
 * Area 4 -- deprovision lifecycle.
 *
 * Uses the package-private ScimGroupSync.clientFactory hook to inject a mock ScimClient.
 */
@ExtendWith(MockitoExtension.class)
class ScimGroupSyncStateTest {

    @Mock KeycloakSession session;
    @Mock RealmModel      realm;
    @Mock ComponentModel  target;
    @Mock ScimClient      client;
    @Mock GroupModel      group;
    @Mock UserModel       user;
    @Mock GroupProvider   groupProvider;
    @Mock UserProvider    userProvider;

    private static final String TARGET_ID    = "target-1";
    private static final String GROUP_ID     = "group-kc-1";
    private static final String GROUP_NAME   = "engineering";
    private static final String USER_ID      = "user-kc-1";
    private static final String SCIM_USER_ID = "scim-user-1";
    private static final String SCIM_GRP_ID  = "scim-grp-1";

    @BeforeEach
    void setUp() {
        ScimGroupSync.clientFactory = (base, token) -> client;

        // target component basics
        when(realm.getComponentsStream()).thenReturn(Stream.of(target));
        when(target.getProviderId()).thenReturn(ScimTargetProviderFactory.ID);
        when(target.getId()).thenReturn(TARGET_ID);
        when(target.getName()).thenReturn("Test Target");

        // minimal valid config
        lenient().when(target.get(ScimTargetProviderFactory.CFG_BASE_URL))
                 .thenReturn("https://scim.example.com");
        lenient().when(target.get(ScimTargetProviderFactory.CFG_TOKEN))
                 .thenReturn("token-abc");
        lenient().when(target.get(ScimTargetProviderFactory.CFG_SYNC_GROUPS))
                 .thenReturn("true");
        lenient().when(target.get(ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER))
                 .thenReturn(null);
        lenient().when(target.get(ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER_REGEX))
                 .thenReturn("false");
        lenient().when(target.get(ScimTargetProviderFactory.CFG_FILTER_GROUP))
                 .thenReturn(GROUP_NAME);
        lenient().when(target.get(ScimTargetProviderFactory.CFG_LOOKUP_STRATEGY))
                 .thenReturn(ScimTargetProviderFactory.LOOKUP_STRATEGY_EXTERNAL_ID_FIRST);
        lenient().when(target.get(ScimTargetProviderFactory.CFG_UNAME_STRATEGY))
                 .thenReturn("username");
        lenient().when(target.get(ScimTargetProviderFactory.CFG_GROUP_MEMBER_REMOVE_FORM))
                 .thenReturn(null);

        // group basics
        lenient().when(group.getId()).thenReturn(GROUP_ID);
        lenient().when(group.getName()).thenReturn(GROUP_NAME);

        // user basics
        lenient().when(user.getId()).thenReturn(USER_ID);
        lenient().when(user.getUsername()).thenReturn("alice");

        // session providers
        lenient().when(session.groups()).thenReturn(groupProvider);
        lenient().when(session.users()).thenReturn(userProvider);

        // group name lookup for resolveInScopeGroups
        lenient().when(groupProvider.searchForGroupByNameStream(
                eq(realm), eq(GROUP_NAME), eq(true), isNull(), isNull()))
                 .thenReturn(Stream.of(group));

        // SCIM group lookup
        lenient().when(client.findGroupByExternalId(GROUP_ID))
                 .thenReturn(new ScimClient.ScimLookupResult(Optional.of(SCIM_GRP_ID), 1));
        lenient().when(client.findGroupIdByDisplayName(GROUP_NAME))
                 .thenReturn(Optional.of(SCIM_GRP_ID));

        // SCIM user lookup
        lenient().when(client.findUserIdByExternalId(USER_ID))
                 .thenReturn(Optional.of(SCIM_USER_ID));
    }

    @AfterEach
    void tearDown() {
        ScimGroupSync.clientFactory = ScimClient::new;
    }

    // =========================================================================
    // Delta flush -- NEW_ADDED transitions to SENT
    // =========================================================================

    @Test
    void delta_newAdded_transitionsToSent_pendingFlagCleared() {
        String addEntry = new GroupMembershipState(TARGET_ID, USER_ID, NEW_ADDED).toValue();
        String pendingFlag = GroupMembershipState.pendingValue(TARGET_ID);

        when(group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME))
                .thenReturn(Stream.of(pendingFlag));
        when(group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.of(addEntry));
        when(session.users().getUserById(realm, USER_ID)).thenReturn(user);
        when(client.patchGroup(eq(SCIM_GRP_ID), anyString())).thenReturn(true);

        ScimGroupSync.processPendingGroupMembershipChanges(
                session, realm, TARGET_ID, ScimGroupSync.MODE_DELTA_ONLY);

        ArgumentCaptor<List> stateCaptor = ArgumentCaptor.forClass(List.class);
        verify(group).setAttribute(eq(GroupMembershipState.ATTRIBUTE_NAME), stateCaptor.capture());

        List<String> written = stateCaptor.getValue();
        assertTrue(written.stream()
                .map(GroupMembershipState::parse)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .anyMatch(e -> e.componentId().equals(TARGET_ID)
                        && e.userId().equals(USER_ID)
                        && e.state() == SENT),
                "entry must be SENT after successful push");

        // pending flag must be cleared
        ArgumentCaptor<List> pendingCaptor = ArgumentCaptor.forClass(List.class);
        verify(group).setAttribute(eq(GroupMembershipState.PENDING_ATTRIBUTE_NAME), pendingCaptor.capture());
        assertFalse(pendingCaptor.getValue().contains(pendingFlag),
                "pending flag must be cleared when no non-SENT entries remain");
    }

    // =========================================================================
    // Delta flush -- NEW_DELETED skipped in DELTA_ONLY mode
    // =========================================================================

    @Test
    void delta_newDeleted_skippedInDeltaOnly_noPatchCall() {
        String delEntry = new GroupMembershipState(TARGET_ID, USER_ID, NEW_DELETED).toValue();
        String pendingFlag = GroupMembershipState.pendingValue(TARGET_ID);

        when(group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME))
                .thenReturn(Stream.of(pendingFlag));
        when(group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.of(delEntry));

        ScimGroupSync.processPendingGroupMembershipChanges(
                session, realm, TARGET_ID, ScimGroupSync.MODE_DELTA_ONLY);

        verify(client, never()).patchGroup(anyString(), anyString());
        // state must not be written (nothing changed)
        verify(group, never()).setAttribute(eq(GroupMembershipState.ATTRIBUTE_NAME), any());
    }

    // =========================================================================
    // Delta flush -- NEW_DELETED flushed in DELTA_DEPROVISION mode
    // =========================================================================

    @Test
    void delta_newDeleted_flushedInDeltaDeprovision_entryRemoved() {
        String delEntry = new GroupMembershipState(TARGET_ID, USER_ID, NEW_DELETED).toValue();
        String pendingFlag = GroupMembershipState.pendingValue(TARGET_ID);

        when(group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME))
                .thenReturn(Stream.of(pendingFlag));
        when(group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.of(delEntry));
        when(session.users().getUserById(realm, USER_ID)).thenReturn(user);
        when(client.patchGroup(eq(SCIM_GRP_ID), anyString())).thenReturn(true);

        // cross-check: no remote members
        when(client.getGroupMembers(SCIM_GRP_ID)).thenReturn(List.of());

        ScimGroupSync.processPendingGroupMembershipChanges(
                session, realm, TARGET_ID, ScimGroupSync.MODE_DELTA_DEPROVISION);

        ArgumentCaptor<List> stateCaptor = ArgumentCaptor.forClass(List.class);
        verify(group).setAttribute(eq(GroupMembershipState.ATTRIBUTE_NAME), stateCaptor.capture());

        List<String> written = stateCaptor.getValue();
        assertTrue(written.stream()
                .map(GroupMembershipState::parse)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .noneMatch(e -> e.componentId().equals(TARGET_ID) && e.userId().equals(USER_ID)),
                "entry must be removed after successful remove push");
    }

    // =========================================================================
    // Delta flush -- PATCH failure leaves entry unchanged
    // =========================================================================

    @Test
    void delta_patchFailure_entryUnchanged_pendingFlagRetained() {
        String addEntry = new GroupMembershipState(TARGET_ID, USER_ID, NEW_ADDED).toValue();
        String pendingFlag = GroupMembershipState.pendingValue(TARGET_ID);

        when(group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME))
                .thenReturn(Stream.of(pendingFlag));
        when(group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.of(addEntry));
        when(session.users().getUserById(realm, USER_ID)).thenReturn(user);
        when(client.patchGroup(anyString(), anyString())).thenReturn(false);

        ScimGroupSync.processPendingGroupMembershipChanges(
                session, realm, TARGET_ID, ScimGroupSync.MODE_DELTA_ONLY);

        // no state write on failure
        verify(group, never()).setAttribute(eq(GroupMembershipState.ATTRIBUTE_NAME), any());
    }

    // =========================================================================
    // Delta flush -- SENT entry is skipped (no HTTP call)
    // =========================================================================

    @Test
    void delta_sentEntry_noPatchCall() {
        String sentEntry = new GroupMembershipState(TARGET_ID, USER_ID, SENT).toValue();
        String pendingFlag = GroupMembershipState.pendingValue(TARGET_ID);

        when(group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME))
                .thenReturn(Stream.of(pendingFlag));
        when(group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.of(sentEntry));

        ScimGroupSync.processPendingGroupMembershipChanges(
                session, realm, TARGET_ID, ScimGroupSync.MODE_DELTA_ONLY);

        verify(client, never()).patchGroup(anyString(), anyString());
    }

    // =========================================================================
    // Delta flush -- cross-check only runs in DELTA_DEPROVISION
    // =========================================================================

    @Test
    void delta_crossCheckNotCalledInDeltaOnly() {
        // group has no pending entries -- nothing to flush, but cross-check must not run
        when(group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME))
                .thenReturn(Stream.of());

        ScimGroupSync.processPendingGroupMembershipChanges(
                session, realm, TARGET_ID, ScimGroupSync.MODE_DELTA_ONLY);

        verify(client, never()).getGroupMembers(anyString());
    }

    // =========================================================================
    // Area 3 -- Resolution safety: full sync aborts on unresolvable member
    // =========================================================================

    @Test
    void fullSync_unresolvableMember_patchNotSent() {
        when(userProvider.getGroupMembersStream(realm, group)).thenReturn(Stream.of(user));
        // user cannot be resolved to a SCIM ID
        when(client.findUserIdByExternalId(USER_ID)).thenReturn(Optional.empty());
        when(client.findUserIdByUserName(any())).thenReturn(Optional.empty());

        ScimGroupSync.processFullGroupSync(session, realm, TARGET_ID);

        verify(client, never()).patchGroup(anyString(), anyString());
    }

    // =========================================================================
    // Area 3 -- Resolution safety: full sync succeeds when all members resolved
    // =========================================================================

    @Test
    void fullSync_allMembersResolved_patchSent() {
        when(userProvider.getGroupMembersStream(realm, group)).thenReturn(Stream.of(user));
        when(group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.of());
        when(group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME))
                .thenReturn(Stream.of());
        when(client.patchGroup(eq(SCIM_GRP_ID), anyString())).thenReturn(true);

        ScimGroupSync.processFullGroupSync(session, realm, TARGET_ID);

        verify(client).patchGroup(eq(SCIM_GRP_ID), anyString());
    }

    // =========================================================================
    // Area 4 -- Deprovision: out-of-scope group, DELETE succeeds -> state cleared
    // =========================================================================

    @Test
    void deprovision_outOfScope_deleteSucceeds_stateClearedOnGroup() {
        String sentEntry = new GroupMembershipState(TARGET_ID, USER_ID, SENT).toValue();
        // group is "previously provisioned" (has state for this target)
        when(groupProvider.getGroupsStream(realm)).thenReturn(Stream.of(group));
        when(group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.of(sentEntry));
        when(group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME))
                .thenReturn(Stream.of());
        // group is out of scope: CFG_FILTER_GROUP=engineering but group name is "old-group"
        when(group.getName()).thenReturn("old-group");
        when(client.deleteGroup(SCIM_GRP_ID)).thenReturn(true);

        ScimGroupSync.deprovisionOutOfScopeGroups(session, realm, TARGET_ID);

        verify(client).deleteGroup(SCIM_GRP_ID);
        // clearGroupState removes all entries for this target
        ArgumentCaptor<List> stateCaptor = ArgumentCaptor.forClass(List.class);
        verify(group, atLeastOnce()).setAttribute(
                eq(GroupMembershipState.ATTRIBUTE_NAME), stateCaptor.capture());
        List<String> finalState = stateCaptor.getValue();
        assertTrue(finalState.stream()
                .map(GroupMembershipState::parse)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .noneMatch(e -> e.componentId().equals(TARGET_ID)),
                "all entries for this target must be cleared after DELETE");
    }

    // =========================================================================
    // Area 4 -- Deprovision: DELETE fails -> state NOT cleared
    // =========================================================================

    @Test
    void deprovision_outOfScope_deleteFails_stateRetained() {
        String sentEntry = new GroupMembershipState(TARGET_ID, USER_ID, SENT).toValue();
        when(groupProvider.getGroupsStream(realm)).thenReturn(Stream.of(group));
        when(group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.of(sentEntry));
        when(group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME))
                .thenReturn(Stream.of());
        when(group.getName()).thenReturn("old-group");
        when(client.deleteGroup(SCIM_GRP_ID)).thenReturn(false);

        ScimGroupSync.deprovisionOutOfScopeGroups(session, realm, TARGET_ID);

        // setAttribute must NOT be called (state retained for retry)
        verify(group, never()).setAttribute(eq(GroupMembershipState.ATTRIBUTE_NAME), any());
    }

    // =========================================================================
    // Area 4 -- Sync paths must not clear state (SENT entries survive full sync)
    // =========================================================================

    @Test
    void fullSync_sentEntriesForOtherTarget_untouched() {
        String otherTargetEntry = new GroupMembershipState("target-2", USER_ID, SENT).toValue();

        when(userProvider.getGroupMembersStream(realm, group)).thenReturn(Stream.of(user));
        when(group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.of(otherTargetEntry));
        when(group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME))
                .thenReturn(Stream.of());
        when(client.patchGroup(eq(SCIM_GRP_ID), anyString())).thenReturn(true);

        ScimGroupSync.processFullGroupSync(session, realm, TARGET_ID);

        ArgumentCaptor<List> stateCaptor = ArgumentCaptor.forClass(List.class);
        verify(group).setAttribute(eq(GroupMembershipState.ATTRIBUTE_NAME), stateCaptor.capture());

        List<String> written = stateCaptor.getValue();
        assertTrue(written.contains(otherTargetEntry),
                "entries for other targets must survive a full sync run");
    }
}
