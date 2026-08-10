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
    void oppositeMembershipOperationResetsTheDuplicateState() {
        ScimEventListenerProvider provider = new ScimEventListenerProvider(null);

        assertFalse(provider.shouldDebounceMembershipEvent(
                "realm", "user", "group", OperationType.CREATE, "target-a", 1_000L));
        assertFalse(provider.shouldDebounceMembershipEvent(
                "realm", "user", "group", OperationType.DELETE, "target-a", 1_100L));
        assertFalse(provider.shouldDebounceMembershipEvent(
                "realm", "user", "group", OperationType.CREATE, "target-a", 1_200L));
        assertTrue(provider.shouldDebounceMembershipEvent(
                "realm", "user", "group", OperationType.CREATE, "target-a", 1_201L));
    }

    @Test
    void structuredMembershipKeysDoNotCollideWhenIdsContainColons() {
        ScimEventListenerProvider provider = new ScimEventListenerProvider(null);

        assertFalse(provider.shouldDebounceMembershipEvent(
                "realm", "user:part", "group", OperationType.CREATE, "target-a", 1_000L));
        assertFalse(provider.shouldDebounceMembershipEvent(
                "realm", "user", "part:group", OperationType.CREATE, "target-a", 1_001L));
    }

    @Test
    void membershipEventIsAllowedWhenDebounceWindowExpires() {
        ScimEventListenerProvider provider = new ScimEventListenerProvider(null);

        assertFalse(provider.shouldDebounceMembershipEvent(
                "realm", "user", "group", OperationType.CREATE, "target-a", 1_000L));
        assertFalse(provider.shouldDebounceMembershipEvent(
                "realm", "user", "group", OperationType.CREATE, "target-a", 3_000L));
    }

    @Test
    void membershipEventIsAllowedWhenTheClockMovesBackwards() {
        ScimEventListenerProvider provider = new ScimEventListenerProvider(null);

        assertFalse(provider.shouldDebounceMembershipEvent(
                "realm", "user", "group", OperationType.CREATE, "target-a", 3_000L));
        assertFalse(provider.shouldDebounceMembershipEvent(
                "realm", "user", "group", OperationType.CREATE, "target-a", 1_000L));
    }

    @Test
    void duplicateUserEventIsDebouncedBeforeTargetFanOut() {
        ScimEventListenerProvider provider = new ScimEventListenerProvider(null);

        assertFalse(provider.shouldDebounceUserEvent("realm", "user", "UPDATE", 1_000L));
        assertTrue(provider.shouldDebounceUserEvent("realm", "user", "UPDATE", 2_999L));
    }

    @Test
    void userEventsAreScopedByRealmUserAndAction() {
        ScimEventListenerProvider provider = new ScimEventListenerProvider(null);

        assertFalse(provider.shouldDebounceUserEvent("realm-a", "user-a", "UPDATE", 1_000L));
        assertFalse(provider.shouldDebounceUserEvent("realm-b", "user-a", "UPDATE", 1_001L));
        assertFalse(provider.shouldDebounceUserEvent("realm-a", "user-b", "UPDATE", 1_002L));
        assertFalse(provider.shouldDebounceUserEvent("realm-a", "user-a", "CREATE", 1_003L));
    }

    @Test
    void structuredUserKeysDoNotCollideWhenIdsContainColons() {
        ScimEventListenerProvider provider = new ScimEventListenerProvider(null);

        assertFalse(provider.shouldDebounceUserEvent("realm:CREATE", "user", "UPDATE", 1_000L));
        assertFalse(provider.shouldDebounceUserEvent("realm", "UPDATE:user", "CREATE", 1_001L));
    }
}
