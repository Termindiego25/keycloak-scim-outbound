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
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static es.diegosr.keycloak_scim_outbound.ldapsync.GroupMembershipState.State.NEW_ADDED;
import static es.diegosr.keycloak_scim_outbound.ldapsync.GroupMembershipState.State.SENT;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Area 4 -- Lifecycle cleanup: deprovisionOutOfScopeGroups.
 *
 * Verifies that:
 *   - clearGroupState is called only after a confirmed remote DELETE (or KC-only cleanup).
 *   - clearGroupState is NOT called when DELETE fails.
 *   - In-scope groups are never touched.
 *   - Groups with no state for this target are not included in the sweep.
 *   - CFG_SYNC_GROUPS=false causes the target to be skipped entirely.
 */
@ExtendWith(MockitoExtension.class)
class ScimGroupSyncDeprovisionTest {

    static final String TARGET_ID   = "target-1";
    static final String BASE_URL    = "https://scim.example.com";
    static final String TOKEN       = "tok";
    static final String GROUP_ID    = "kc-group-1";
    static final String GROUP_NAME  = "old-group";
    static final String SCIM_GRP_ID = "scim-grp-1";
    static final String USER_A_ID   = "user-a";

    @Mock KeycloakSession session;
    @Mock RealmModel      realm;
    @Mock ComponentModel  target;
    @Mock ScimClient      client;
    @Mock GroupModel      group;
    @Mock GroupProvider   groupProvider;

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
        // Filter: only "active-group" is in scope; "old-group" is out of scope
        lenient().when(target.get(ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER)).thenReturn("active-group");
        lenient().when(target.get(ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER_REGEX)).thenReturn("false");
        lenient().when(target.get(ScimTargetProviderFactory.CFG_FILTER_GROUP)).thenReturn(null);
        lenient().when(target.get(ScimTargetProviderFactory.CFG_LOOKUP_STRATEGY))
                 .thenReturn(ScimTargetProviderFactory.LOOKUP_STRATEGY_EXTERNAL_ID_FIRST);

        when(session.groups()).thenReturn(groupProvider);

        when(group.getId()).thenReturn(GROUP_ID);
        when(group.getName()).thenReturn(GROUP_NAME); // out of scope
        // group has a state entry for target-1 -> previously provisioned
        String stateEntry = new GroupMembershipState(TARGET_ID, USER_A_ID, SENT).toValue();
        when(group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.of(stateEntry));
        when(group.getAttributeStream(GroupMembershipState.PENDING_ATTRIBUTE_NAME))
                .thenReturn(Stream.empty());

        when(groupProvider.getGroupsStream(realm)).thenReturn(Stream.of(group));
    }

    @AfterEach
    void tearDown() {
        ScimGroupSync.clientFactory = ScimClient::new;
    }

    // -------------------------------------------------------------------------
    // Delete succeeds -> clearGroupState called
    // -------------------------------------------------------------------------

    @Test
    void deleteSucceeds_groupStateCleared() {
        when(client.findGroupByExternalId(GROUP_ID))
                .thenReturn(new ScimClient.ScimLookupResult(Optional.of(SCIM_GRP_ID), 1));
        when(client.deleteGroup(SCIM_GRP_ID)).thenReturn(true);

        ScimGroupSync.deprovisionOutOfScopeGroups(session, realm, TARGET_ID);

        verify(client, times(1)).deleteGroup(SCIM_GRP_ID);
        // After successful DELETE, setAttribute must be called to clear the state
        ArgumentCaptor<List> stateCaptor = ArgumentCaptor.forClass(List.class);
        verify(group, atLeastOnce()).setAttribute(eq(GroupMembershipState.ATTRIBUTE_NAME), stateCaptor.capture());
        // The cleared list must contain no entries for target-1
        List<String> writtenState = stateCaptor.getValue();
        boolean hasTarget1Entry = writtenState.stream()
                .map(GroupMembershipState::parse)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .anyMatch(e -> e.componentId().equals(TARGET_ID));
        assertFalse(hasTarget1Entry, "All target-1 entries must be removed after successful DELETE");
    }

    // -------------------------------------------------------------------------
    // Delete fails -> clearGroupState NOT called
    // -------------------------------------------------------------------------

    @Test
    void deleteFails_groupStateNotCleared() {
        when(client.findGroupByExternalId(GROUP_ID))
                .thenReturn(new ScimClient.ScimLookupResult(Optional.of(SCIM_GRP_ID), 1));
        when(client.deleteGroup(SCIM_GRP_ID)).thenReturn(false);

        ScimGroupSync.deprovisionOutOfScopeGroups(session, realm, TARGET_ID);

        verify(client, times(1)).deleteGroup(SCIM_GRP_ID);
        verify(group, never()).setAttribute(eq(GroupMembershipState.ATTRIBUTE_NAME), any());
    }

    // -------------------------------------------------------------------------
    // Group not found remotely -> KC-only cleanup
    // -------------------------------------------------------------------------

    @Test
    void groupNotFoundRemotely_kcAttributesClearedWithoutDelete() {
        when(client.findGroupByExternalId(GROUP_ID))
                .thenReturn(new ScimClient.ScimLookupResult(Optional.empty(), 0));
        when(client.findGroupIdByDisplayName(GROUP_NAME)).thenReturn(Optional.empty());

        ScimGroupSync.deprovisionOutOfScopeGroups(session, realm, TARGET_ID);

        verify(client, never()).deleteGroup(any());
        // KC attributes must still be cleared
        verify(group, atLeastOnce()).setAttribute(eq(GroupMembershipState.ATTRIBUTE_NAME), any());
    }

    // -------------------------------------------------------------------------
    // In-scope group is not touched
    // -------------------------------------------------------------------------

    @Test
    void inScopeGroup_notTouched() {
        when(group.getName()).thenReturn("active-group"); // now in scope

        ScimGroupSync.deprovisionOutOfScopeGroups(session, realm, TARGET_ID);

        verify(client, never()).deleteGroup(any());
        verify(group, never()).setAttribute(eq(GroupMembershipState.ATTRIBUTE_NAME), any());
    }

    // -------------------------------------------------------------------------
    // Group with no state for this target is not included
    // -------------------------------------------------------------------------

    @Test
    void groupWithNoStateForTarget_notIncluded() {
        // Override: group has state for a different target only
        String otherEntry = new GroupMembershipState("other-target", USER_A_ID, SENT).toValue();
        when(group.getAttributeStream(GroupMembershipState.ATTRIBUTE_NAME))
                .thenReturn(Stream.of(otherEntry));

        ScimGroupSync.deprovisionOutOfScopeGroups(session, realm, TARGET_ID);

        verify(client, never()).deleteGroup(any());
        verify(group, never()).setAttribute(eq(GroupMembershipState.ATTRIBUTE_NAME), any());
    }

    // -------------------------------------------------------------------------
    // CFG_SYNC_GROUPS=false -> target skipped entirely
    // -------------------------------------------------------------------------

    @Test
    void syncGroupsFalse_targetSkipped() {
        when(target.get(ScimTargetProviderFactory.CFG_SYNC_GROUPS)).thenReturn("false");

        ScimGroupSync.deprovisionOutOfScopeGroups(session, realm, TARGET_ID);

        verify(client, never()).deleteGroup(any());
        verify(group, never()).setAttribute(any(), any());
    }
}
