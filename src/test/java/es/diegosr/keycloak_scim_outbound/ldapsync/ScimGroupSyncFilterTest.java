package es.diegosr.keycloak_scim_outbound.ldapsync;

import es.diegosr.keycloak_scim_outbound.ui.ScimTargetProviderFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.component.ComponentModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Area 6 -- filter configuration.
 * Tests ScimGroupSync.isGroupInScope (package-private static method).
 * Same package as ScimGroupSync, so no reflection needed.
 * No session or realm required -- only a ComponentModel mock.
 */
@ExtendWith(MockitoExtension.class)
class ScimGroupSyncFilterTest {

    @Mock
    ComponentModel target;

    private void configureFilter(String filter, String useRegex) {
        lenient().when(target.get(ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER))
                 .thenReturn(filter);
        lenient().when(target.get(ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER_REGEX))
                 .thenReturn(useRegex);
        lenient().when(target.get(ScimTargetProviderFactory.CFG_FILTER_GROUP))
                 .thenReturn(null);
    }

    private void configureFilterGroup(String filterGroup) {
        lenient().when(target.get(ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER))
                 .thenReturn(null);
        lenient().when(target.get(ScimTargetProviderFactory.CFG_SYNC_GROUPS_FILTER_REGEX))
                 .thenReturn("false");
        lenient().when(target.get(ScimTargetProviderFactory.CFG_FILTER_GROUP))
                 .thenReturn(filterGroup);
    }

    // -------------------------------------------------------------------------
    // Fallback to CFG_FILTER_GROUP
    // -------------------------------------------------------------------------

    @Test
    void noFilter_matchesFilterGroup() {
        configureFilterGroup("engineering");
        assertTrue(ScimGroupSync.isGroupInScope(target, "engineering"));
    }

    @Test
    void noFilter_doesNotMatchOtherGroup() {
        configureFilterGroup("engineering");
        assertFalse(ScimGroupSync.isGroupInScope(target, "hr"));
    }

    // -------------------------------------------------------------------------
    // Comma-separated list (regex=false)
    // -------------------------------------------------------------------------

    @Test
    void commaList_firstEntryMatches() {
        configureFilter("engineering,hr", "false");
        assertTrue(ScimGroupSync.isGroupInScope(target, "engineering"));
    }

    @Test
    void commaList_secondEntryMatches() {
        configureFilter("engineering,hr", "false");
        assertTrue(ScimGroupSync.isGroupInScope(target, "hr"));
    }

    @Test
    void commaList_unlistedGroupDoesNotMatch() {
        configureFilter("engineering,hr", "false");
        assertFalse(ScimGroupSync.isGroupInScope(target, "finance"));
    }

    @Test
    void commaList_whitespaceAroundNames_trimmedCorrectly() {
        configureFilter(" engineering , hr ", "false");
        assertTrue(ScimGroupSync.isGroupInScope(target, "engineering"));
        assertTrue(ScimGroupSync.isGroupInScope(target, "hr"));
    }

    // -------------------------------------------------------------------------
    // Regex mode
    // -------------------------------------------------------------------------

    @Test
    void regex_matchingPattern_returnsTrue() {
        configureFilter("eng.*", "true");
        assertTrue(ScimGroupSync.isGroupInScope(target, "engineering"));
    }

    @Test
    void regex_nonMatchingPattern_returnsFalse() {
        configureFilter("eng.*", "true");
        assertFalse(ScimGroupSync.isGroupInScope(target, "hr"));
    }

    @Test
    void regex_invalidPattern_returnsFalseWithoutException() {
        configureFilter("[invalid", "true");
        assertDoesNotThrow(() -> ScimGroupSync.isGroupInScope(target, "anything"));
        assertFalse(ScimGroupSync.isGroupInScope(target, "anything"));
    }

    // -------------------------------------------------------------------------
    // Null guard
    // -------------------------------------------------------------------------

    @Test
    void nullGroupName_alwaysReturnsFalse() {
        configureFilter("engineering,hr", "false");
        assertFalse(ScimGroupSync.isGroupInScope(target, null));
    }
}
