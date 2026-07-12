package es.diegosr.keycloak_scim_outbound.ldapsync;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static es.diegosr.keycloak_scim_outbound.ldapsync.MembershipState.State.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for MembershipState serialization and parsing.
 * Parallel to GroupMembershipStateTest for the /Users state record.
 */
class MembershipStateTest {

    @Test
    void roundTrip_newAdded() {
        MembershipState original = new MembershipState("comp-1", "group-1", NEW_ADDED);
        Optional<MembershipState> parsed = MembershipState.parse(original.toValue());

        assertTrue(parsed.isPresent());
        assertEquals("comp-1", parsed.get().componentId());
        assertEquals("group-1", parsed.get().groupId());
        assertEquals(NEW_ADDED, parsed.get().state());
    }

    @Test
    void roundTrip_sent() {
        MembershipState original = new MembershipState("comp-2", "group-2", SENT);
        Optional<MembershipState> parsed = MembershipState.parse(original.toValue());

        assertTrue(parsed.isPresent());
        assertEquals(SENT, parsed.get().state());
    }

    @Test
    void roundTrip_newDeleted() {
        MembershipState original = new MembershipState("comp-3", "group-3", NEW_DELETED);
        Optional<MembershipState> parsed = MembershipState.parse(original.toValue());

        assertTrue(parsed.isPresent());
        assertEquals(NEW_DELETED, parsed.get().state());
    }

    @Test
    void parse_nullInput_returnsEmpty() {
        assertTrue(MembershipState.parse(null).isEmpty());
    }

    @Test
    void parse_blankInput_returnsEmpty() {
        assertTrue(MembershipState.parse("").isEmpty());
    }

    @Test
    void parse_malformedJson_returnsEmpty() {
        assertTrue(MembershipState.parse("not-json").isEmpty());
    }

    @Test
    void parse_unknownState_returnsEmpty() {
        assertTrue(MembershipState.parse(
                "{\"c\":\"c1\",\"g\":\"g1\",\"s\":\"UNKNOWN\"}").isEmpty());
    }

    @Test
    void pendingValue_format() {
        assertEquals("comp-1:1", MembershipState.pendingValue("comp-1"));
    }

    @Test
    void roundTrip_specialCharsInIds() {
        String compId = "comp-with-\"quote\"";
        String groupId = "group-with-\\backslash";
        MembershipState original = new MembershipState(compId, groupId, SENT);
        Optional<MembershipState> parsed = MembershipState.parse(original.toValue());

        assertTrue(parsed.isPresent());
        assertEquals(compId, parsed.get().componentId());
        assertEquals(groupId, parsed.get().groupId());
    }
}
