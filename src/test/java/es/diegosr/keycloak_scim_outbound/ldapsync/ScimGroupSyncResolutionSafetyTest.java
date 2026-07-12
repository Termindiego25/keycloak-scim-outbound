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

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static es.diegosr.keycloak_scim_outbound.ldapsync.GroupMembershipState.State.NEW_ADDED;
import static es.diegosr.keycloak_scim_outbound.ldapsync.GroupMembershipState.State.NEW_DELETED;
import static es.diegosr.keycloak_scim_outbound.ldapsync.GroupMembershipState.State.SENT;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Area 3 -- Partial lookup failure abort guards in ScimGroupSync.
 *
 * Verifies that processFullGroupSync and crossCheckGroupMembers (triggered via
 * MODE_DELTA_DEPROVISION) abort destructive PATCH calls when any member's SCIM
 * user ID cannot be resolved, and that other groups in the same run are unaffected.
 */
@ExtendWith(MockitoExtension.class)
class ScimGroupSyncResolutionSafetyTest {

    static final String TARGET_ID   = "target-1";
    static final String BASE_URL    = "https://scim.example.com";
    static final String TOKEN       = "tok";
    static final String GROUP_ID    = "kc-group-1";
    static final String GROUP_NAME  = "engineering";
    static final String SCIM_GRP_ID = "scim-grp-1";
    static final String USER_A_ID   = "user-a";
    static final String USER_B_ID   = "user-b";
    static final String SCIM_A_ID   = "scim-a";

    @Mock KeycloakSession   session;
    @Mock RealmModel        realm;
    @Mock ComponentModel    target;
    @Mock ScimClient        client;
    @Mock GroupModel        group;
    @Mock UserModel         userA;
    @Mock UserModel         userB;
    @Mock UserProvider      userProvider;
    @Mock GroupProvider     groupProvider;

    @BeforeEach
    void setUp() {
        ScimGroupSync.clientFactory = (b, t) -> client;

        when(realm.getName()).thenReturn("test-realm");
        when(realm.getComponentsStream()).thenReturn(Stream.of(target));
        when(target.getProviderId()).thenReturn(ScimTargetProviderFactory.ID);
        when(target.getId()).thenReturn(TARGET_ID);
        when(target.getName()).thenReturn("Test Target");
        lenient().when(target.get(ScimTargetProviderFactory.CFG_BASE_URL)).thenReturn(BASE_URL);
        lenient().when(target.get(ScimTargetProviderFactory.CFG_TOKEN)).thenReturn(TOKEN);
        lenient().when(target.get(ScimTargetProviderFactory.CFG_SYNC_GROUPS)).thenReturn("true");
        lenient().when(target.get(ScimTargetProviderFactory.CFG_LOOKUP_STRATEGY))
                 .thenReturn(ScimTargetProviderFactory.LOOKUP_STRATEGY_EXTERNAL_ID_FIRST);
        lenient().when(target.get(ScimTargetProviderFactory.CFG_UNAME_STRATEGY)).thenReturn("username");
        lenient().when(target.get(ScimTargetProviderFactory.CFG_FILTER_GROUP)).thenReturn(null);
        lenient().when(target.get(ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER)).thenReturn(GROUP_NAME);
        lenient().when(target.get(ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER_REGEX)).thenReturn("false");

        when(session.groups()).thenReturn(groupProvider);
        when(session.users()).thenReturn(userProvider);

        when(group.getId()).thenReturn(GROUP_ID);
        when(group.getName()).thenReturn(GROUP_NAME);
        when(group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.of(new GroupMembershipState(TARGET_ID, USER_A_ID, NEW_ADDED).toValue()));
        when(group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME))
                .thenReturn(Stream.of(GroupMembershipState.pendingValue(TARGET_ID)));

        when(userA.getId()).thenReturn(USER_A_ID);
        when(userA.getUsername()).thenReturn("alice");
        when(userB.getId()).thenReturn(USER_B_ID);
        when(userB.getUsername()).thenReturn("bob");

        when(groupProvider.searchForGroupByNameStream(eq(realm), eq(GROUP_NAME), eq(true), isNull(), isNull()))
                .thenReturn(Stream.of(group));
    }

    @AfterEach
    void tearDown() {
        ScimGroupSync.clientFactory = ScimClient::new;
    }

    // -------------------------------------------------------------------------
    // processFullGroupSync -- resolution abort
    // -------------------------------------------------------------------------

    @Test
    void fullSync_oneUnresolvableMember_patchNotCalled() {
        // userA resolves, userB does not
        when(userProvider.getGroupMembersStream(realm, group))
                .thenReturn(Stream.of(userA, userB));

        ScimClient.ScimLookupResult foundGrp = new ScimClient.ScimLookupResult(Optional.of(SCIM_GRP_ID), 1);
        when(client.findGroupByExternalId(GROUP_ID)).thenReturn(foundGrp);

        when(client.findUserIdByExternalId(USER_A_ID)).thenReturn(Optional.of(SCIM_A_ID));
        when(client.findUserIdByExternalId(USER_B_ID)).thenReturn(Optional.empty());
        when(client.findUserIdByUserName("bob")).thenReturn(Optional.empty());

        ScimGroupSync.processFullGroupSync(session, realm, TARGET_ID);

        verify(client, never()).patchGroup(any(), any());
    }

    @Test
    void fullSync_allMembersResolvable_patchIsCalled() {
        when(userProvider.getGroupMembersStream(realm, group))
                .thenReturn(Stream.of(userA));

        ScimClient.ScimLookupResult foundGrp = new ScimClient.ScimLookupResult(Optional.of(SCIM_GRP_ID), 1);
        when(client.findGroupByExternalId(GROUP_ID)).thenReturn(foundGrp);
        when(client.findUserIdByExternalId(USER_A_ID)).thenReturn(Optional.of(SCIM_A_ID));
        when(client.patchGroup(eq(SCIM_GRP_ID), any())).thenReturn(true);

        when(group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.empty());

        ScimGroupSync.processFullGroupSync(session, realm, TARGET_ID);

        verify(client, times(1)).patchGroup(eq(SCIM_GRP_ID), any());
    }

    @Test
    void fullSync_unresolvableMember_otherGroupStillProcessed() {
        GroupModel group2 = mock(GroupModel.class);
        when(group2.getId()).thenReturn("kc-group-2");
        when(group2.getName()).thenReturn("hr");
        when(group2.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME)).thenReturn(Stream.empty());
        when(group2.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME)).thenReturn(Stream.empty());

        lenient().when(target.get(ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER))
                 .thenReturn("engineering,hr");

        when(groupProvider.searchForGroupByNameStream(eq(realm), eq("engineering"), eq(true), isNull(), isNull()))
                .thenReturn(Stream.of(group));
        when(groupProvider.searchForGroupByNameStream(eq(realm), eq("hr"), eq(true), isNull(), isNull()))
                .thenReturn(Stream.of(group2));

        // group1: userB unresolvable -> abort
        when(userProvider.getGroupMembersStream(realm, group)).thenReturn(Stream.of(userB));
        when(client.findGroupByExternalId(GROUP_ID))
                .thenReturn(new ScimClient.ScimLookupResult(Optional.of(SCIM_GRP_ID), 1));
        when(client.findUserIdByExternalId(USER_B_ID)).thenReturn(Optional.empty());
        when(client.findUserIdByUserName("bob")).thenReturn(Optional.empty());

        // group2: no members -> replace with empty list should succeed
        when(userProvider.getGroupMembersStream(realm, group2)).thenReturn(Stream.empty());
        when(client.findGroupByExternalId("kc-group-2"))
                .thenReturn(new ScimClient.ScimLookupResult(Optional.of("scim-grp-2"), 1));
        when(client.patchGroup(eq("scim-grp-2"), any())).thenReturn(true);

        ScimGroupSync.processFullGroupSync(session, realm, TARGET_ID);

        // group1 must not have triggered a patch; group2 must have
        verify(client, never()).patchGroup(eq(SCIM_GRP_ID), any());
        verify(client, times(1)).patchGroup(eq("scim-grp-2"), any());
    }

    // -------------------------------------------------------------------------
    // crossCheckGroupMembers -- resolution abort (via MODE_DELTA_DEPROVISION)
    // -------------------------------------------------------------------------

    @Test
    void crossCheck_unresolvableLocalMember_noRemoveSent() {
        // Set up delta flush with no pending entries so only cross-check runs
        when(group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.empty());
        when(group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME))
                .thenReturn(Stream.empty());

        // Remote has one member
        ScimClient.ScimLookupResult foundGrp = new ScimClient.ScimLookupResult(Optional.of(SCIM_GRP_ID), 1);
        when(client.findGroupByExternalId(GROUP_ID)).thenReturn(foundGrp);
        when(client.getGroupMembers(SCIM_GRP_ID)).thenReturn(List.of("scim-remote-1"));

        // Local member userA cannot be resolved
        when(userProvider.getGroupMembersStream(realm, group)).thenReturn(Stream.of(userA));
        when(client.findUserIdByExternalId(USER_A_ID)).thenReturn(Optional.empty());
        when(client.findUserIdByUserName("alice")).thenReturn(Optional.empty());

        ScimGroupSync.processPendingGroupMembershipChanges(
                session, realm, TARGET_ID, ScimGroupSync.MODE_DELTA_DEPROVISION);

        verify(client, never()).patchGroup(eq(SCIM_GRP_ID), contains("remove"));
    }

    @Test
    void crossCheck_groupNotFoundRemotely_noAutoCreate() {
        when(group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.empty());
        when(group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME))
                .thenReturn(Stream.empty());

        // resolveScimGroupId returns empty for both strategies
        when(client.findGroupByExternalId(GROUP_ID))
                .thenReturn(new ScimClient.ScimLookupResult(Optional.empty(), 0));
        when(client.findGroupIdByDisplayName(GROUP_NAME)).thenReturn(Optional.empty());

        ScimGroupSync.processPendingGroupMembershipChanges(
                session, realm, TARGET_ID, ScimGroupSync.MODE_DELTA_DEPROVISION);

        verify(client, never()).createGroup(any());
        verify(client, never()).patchGroup(any(), any());
    }

    // -------------------------------------------------------------------------
    // Ambiguous externalId falls back to displayName
    // -------------------------------------------------------------------------

    @Test
    void resolveGroupId_ambiguousExternalId_fallsBackToDisplayName() {
        when(userProvider.getGroupMembersStream(realm, group)).thenReturn(Stream.empty());

        // externalId returns 2 results (ambiguous)
        when(client.findGroupByExternalId(GROUP_ID))
                .thenReturn(new ScimClient.ScimLookupResult(Optional.empty(), 2));
        // displayName lookup succeeds
        when(client.findGroupIdByDisplayName(GROUP_NAME)).thenReturn(Optional.of(SCIM_GRP_ID));
        when(client.patchGroup(eq(SCIM_GRP_ID), any())).thenReturn(true);
        when(group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.empty());

        ScimGroupSync.processFullGroupSync(session, realm, TARGET_ID);

        verify(client, times(1)).findGroupIdByDisplayName(GROUP_NAME);
        verify(client, times(1)).patchGroup(eq(SCIM_GRP_ID), any());
    }

    // -------------------------------------------------------------------------
    // Name-only strategy skips externalId call
    // -------------------------------------------------------------------------

    @Test
    void nameOnlyStrategy_externalIdCallSkipped() {
        lenient().when(target.get(ScimTargetProviderFactory.CFG_LOOKUP_STRATEGY))
                 .thenReturn(ScimTargetProviderFactory.LOOKUP_STRATEGY_NAME_ONLY);

        when(userProvider.getGroupMembersStream(realm, group)).thenReturn(Stream.empty());
        when(client.findGroupIdByDisplayName(GROUP_NAME)).thenReturn(Optional.of(SCIM_GRP_ID));
        when(client.patchGroup(eq(SCIM_GRP_ID), any())).thenReturn(true);
        when(group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.empty());

        ScimGroupSync.processFullGroupSync(session, realm, TARGET_ID);

        verify(client, never()).findGroupByExternalId(any());
        verify(client, times(1)).findGroupIdByDisplayName(GROUP_NAME);
    }
}
