package es.diegosr.keycloak_scim_outbound.ldapsync;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static es.diegosr.keycloak_scim_outbound.ldapsync.GroupMembershipState.State.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for GroupMembershipState serialization and parsing.
 * Validates the state record used by ScimGroupSync as a foundation for
 * higher-level sync tests.
 */
class GroupMembershipStateTest {

    @Test
    void roundTrip_newAdded() {
        GroupMembershipState original = new GroupMembershipState("comp-1", "user-1", NEW_ADDED);
        Optional<GroupMembershipState> parsed = GroupMembershipState.parse(original.toValue());

        assertTrue(parsed.isPresent());
        assertEquals("comp-1", parsed.get().componentId());
        assertEquals("user-1", parsed.get().userId());
        assertEquals(NEW_ADDED, parsed.get().state());
    }

    @Test
    void roundTrip_sent() {
        GroupMembershipState original = new GroupMembershipState("comp-2", "user-2", SENT);
        Optional<GroupMembershipState> parsed = GroupMembershipState.parse(original.toValue());

        assertTrue(parsed.isPresent());
        assertEquals(SENT, parsed.get().state());
    }

    @Test
    void roundTrip_newDeleted() {
        GroupMembershipState original = new GroupMembershipState("comp-3", "user-3", NEW_DELETED);
        Optional<GroupMembershipState> parsed = GroupMembershipState.parse(original.toValue());

        assertTrue(parsed.isPresent());
        assertEquals(NEW_DELETED, parsed.get().state());
    }

    @Test
    void parse_nullInput_returnsEmpty() {
        assertTrue(GroupMembershipState.parse(null).isEmpty());
    }

    @Test
    void parse_blankInput_returnsEmpty() {
        assertTrue(GroupMembershipState.parse("   ").isEmpty());
    }

    @Test
    void parse_malformedJson_returnsEmpty() {
        assertTrue(GroupMembershipState.parse("{not-json}").isEmpty());
    }

    @Test
    void parse_unknownState_returnsEmpty() {
        assertTrue(GroupMembershipState.parse(
                "{\"c\":\"c1\",\"u\":\"u1\",\"s\":\"INVALID_STATE\"}").isEmpty());
    }

    @Test
    void pendingValue_format() {
        assertEquals("comp-1:1", GroupMembershipState.pendingValue("comp-1"));
    }

    @Test
    void removeAllForComponent_keepsOtherTargetEntries() {
        List<String> values = List.of(
                new GroupMembershipState("comp-1", "user-a", NEW_ADDED).toValue(),
                new GroupMembershipState("comp-2", "user-b", SENT).toValue(),
                new GroupMembershipState("comp-1", "user-c", NEW_DELETED).toValue()
        );

        List<String> result = GroupMembershipState.removeAllForComponent(values, "comp-1");

        assertEquals(1, result.size());
        Optional<GroupMembershipState> remaining = GroupMembershipState.parse(result.get(0));
        assertTrue(remaining.isPresent());
        assertEquals("comp-2", remaining.get().componentId());
    }

    @Test
    void roundTrip_specialCharsInIds() {
        String compId = "comp-with-\"quote\"";
        String userId = "user-with-\\backslash";
        GroupMembershipState original = new GroupMembershipState(compId, userId, SENT);
        Optional<GroupMembershipState> parsed = GroupMembershipState.parse(original.toValue());

        assertTrue(parsed.isPresent());
        assertEquals(compId, parsed.get().componentId());
        assertEquals(userId, parsed.get().userId());
    }
}
