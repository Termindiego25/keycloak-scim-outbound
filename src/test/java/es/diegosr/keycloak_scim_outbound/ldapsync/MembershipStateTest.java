package es.diegosr.keycloak_scim_outbound.ldapsync;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MembershipStateTest {

    @Test
    void findsMembershipStateIndependentlyPerTarget() {
        MembershipState targetA = new MembershipState(
                "target-a", "group", MembershipState.State.SENT);
        MembershipState targetB = new MembershipState(
                "target-b", "group", MembershipState.State.NEW_DELETED);

        List<String> values = List.of(targetA.toValue(), targetB.toValue());

        assertEquals(targetA, MembershipState.findForComponent(values, "target-a").orElseThrow());
        assertEquals(targetB, MembershipState.findForComponent(values, "target-b").orElseThrow());
    }

    @Test
    void serializedStateRoundTripsIdsContainingDelimitersAndEscapes() {
        MembershipState original = new MembershipState(
                "target:with\"quote", "group:with\\slash", MembershipState.State.NEW_ADDED);

        assertEquals(original, MembershipState.parse(original.toValue()).orElseThrow());
    }

    @Test
    void malformedValuesDoNotHideAValidTargetState() {
        MembershipState valid = new MembershipState(
                "target", "group", MembershipState.State.NEW_ADDED);

        assertEquals(valid, MembershipState.findForComponent(
                List.of("not-json", valid.toValue()), "target").orElseThrow());
        assertTrue(MembershipState.parse("not-json").isEmpty());
    }

    @Test
    void pendingFlagsRemainDistinctPerTarget() {
        assertNotEquals(
                MembershipState.pendingValue("target"),
                MembershipState.pendingValue("target:1"));
    }
}
