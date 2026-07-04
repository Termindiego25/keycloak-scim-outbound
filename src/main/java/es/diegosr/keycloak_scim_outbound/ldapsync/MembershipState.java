package es.diegosr.keycloak_scim_outbound.ldapsync;

import java.util.List;
import java.util.Optional;

/**
 * Represents one entry of the multi-valued user attribute
 * "ldapSyncNotifier.filterGroupMembership".
 *
 * Serialized format per value: "<componentId>:<groupName>:<state>"
 * where state is one of NEW_ADDED, NEW_DELETED, SENT.
 *
 * - NEW_ADDED   : user gained membership in the target's filter group; SCIM push pending.
 * - SENT        : membership add was successfully pushed to SCIM; no action needed.
 * - NEW_DELETED : user lost membership in the target's filter group; SCIM deprovision pending.
 *                 (once successfully pushed, the entry is removed entirely -- there is no
 *                  "removed and sent" state, since there's nothing left to track.)
 */
public record MembershipState(String componentId, String groupName, State state) {

    public static final String ATTRIBUTE_NAME = "ldapSyncNotifier.filterGroupMembership";

    public enum State { NEW_ADDED, NEW_DELETED, SENT }

    public String toValue() {
        return componentId + ":" + groupName + ":" + state.name();
    }

    public static Optional<MembershipState> parse(String value) {
        if (value == null) return Optional.empty();
        String[] parts = value.split(":", 3);
        if (parts.length != 3) return Optional.empty();
        try {
            return Optional.of(new MembershipState(parts[0], parts[1], State.valueOf(parts[2])));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    public static Optional<MembershipState> findForComponent(List<String> values, String componentId) {
        return values.stream()
                .map(MembershipState::parse)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .filter(s -> s.componentId().equals(componentId))
                .findFirst();
    }
}
