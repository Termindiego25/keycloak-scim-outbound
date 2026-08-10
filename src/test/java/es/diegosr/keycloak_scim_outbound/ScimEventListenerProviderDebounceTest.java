package es.diegosr.keycloak_scim_outbound;

import org.junit.jupiter.api.Test;
import org.keycloak.events.admin.OperationType;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScimEventListenerProviderDebounceTest {

    @Test
    void membershipEventsAreDebouncedIndependentlyPerTarget() {
        ScimEventListenerProvider provider = new ScimEventListenerProvider(null);

        assertFalse(provider.shouldDebounceMembershipEvent(
                "realm", "user", "group", OperationType.CREATE, "target-a", 1_000L));
        assertFalse(provider.shouldDebounceMembershipEvent(
                "realm", "user", "group", OperationType.CREATE, "target-b", 1_000L));
    }

    @Test
    void duplicateMembershipEventForSameTargetIsDebounced() {
        ScimEventListenerProvider provider = new ScimEventListenerProvider(null);

        assertFalse(provider.shouldDebounceMembershipEvent(
                "realm", "user", "group", OperationType.CREATE, "target-a", 1_000L));
        assertTrue(provider.shouldDebounceMembershipEvent(
                "realm", "user", "group", OperationType.CREATE, "target-a", 2_999L));
    }

    @Test
    void differentMembershipOperationsAreNotDebouncedTogether() {
        ScimEventListenerProvider provider = new ScimEventListenerProvider(null);

        assertFalse(provider.shouldDebounceMembershipEvent(
                "realm", "user", "group", OperationType.CREATE, "target-a", 1_000L));
        assertFalse(provider.shouldDebounceMembershipEvent(
                "realm", "user", "group", OperationType.DELETE, "target-a", 1_001L));
    }

    @Test
    void membershipEventIsAllowedWhenDebounceWindowExpires() {
        ScimEventListenerProvider provider = new ScimEventListenerProvider(null);

        assertFalse(provider.shouldDebounceMembershipEvent(
                "realm", "user", "group", OperationType.CREATE, "target-a", 1_000L));
        assertFalse(provider.shouldDebounceMembershipEvent(
                "realm", "user", "group", OperationType.CREATE, "target-a", 3_000L));
    }
}
