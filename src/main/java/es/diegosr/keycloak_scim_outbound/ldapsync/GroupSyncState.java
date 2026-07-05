package es.diegosr.keycloak_scim_outbound.ldapsync;

import org.keycloak.models.GroupModel;
import org.keycloak.models.RealmModel;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Tracks the SCIM provisioning state of a Keycloak group, per SCIM target (componentId).
 *
 * Storage layout:
 *   GroupModel attribute "scim.outbound.state.<componentId>" -> one of "NEEDS_SYNC", "SYNCED", "NEEDS_DELETE"
 *
 *   The group's attribute is written via GroupModel.setAttribute(), which always targets
 *   Keycloak's local group store (groups are not federated to LDAP the same way users are,
 *   so no ReadOnlyException bypass is needed here).
 *
 * Pending index:
 *   GroupModel attribute "scim.outbound.pending" -> multi-valued list of componentIds that
 *   have an un-delivered state for this group. Used by the sweep to avoid iterating every
 *   group in the realm; only groups with this attribute set are processed.
 *
 * State machine:
 *   (no attribute)  --group enters scope--->  NEEDS_SYNC  --push ok--->  SYNCED
 *   SYNCED          --group renamed------->   NEEDS_SYNC  --push ok--->  SYNCED
 *   SYNCED          --group leaves scope--->  NEEDS_DELETE --push ok--->  (attributes removed)
 */
public final class GroupSyncState {

    /** Prefix for the per-target state attribute on GroupModel. Full key: STATE_ATTR_PREFIX + componentId */
    public static final String STATE_ATTR_PREFIX = "scim.outbound.state.";

    /**
     * Multi-valued GroupModel attribute listing componentIds that currently have an
     * un-delivered (NEEDS_SYNC or NEEDS_DELETE) state entry. Used to build the pending
     * candidate set without iterating all groups.
     */
    public static final String PENDING_ATTR = "scim.outbound.pending";

    public enum State {
        NEEDS_SYNC,   // group must be created/updated at the SCIM target
        SYNCED,       // group is up-to-date at the SCIM target
        NEEDS_DELETE  // group must be deleted from the SCIM target
    }

    private GroupSyncState() {}

    // -- State attribute helpers ----------------------------------------------

    public static String stateAttr(String componentId) {
        return STATE_ATTR_PREFIX + componentId;
    }

    public static Optional<State> getState(GroupModel group, String componentId) {
        String v = group.getFirstAttribute(stateAttr(componentId));
        if (v == null || v.isBlank()) return Optional.empty();
        try {
            return Optional.of(State.valueOf(v));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    public static void setState(GroupModel group, String componentId, State state) {
        group.setAttribute(stateAttr(componentId), List.of(state.name()));
        addPendingFlag(group, componentId);
    }

    public static void clearState(GroupModel group, String componentId) {
        group.removeAttribute(stateAttr(componentId));
        removePendingFlag(group, componentId);
    }

    // -- Pending-flag helpers -------------------------------------------------

    public static boolean hasPendingFlag(GroupModel group, String componentId) {
        return group.getAttributeStream(PENDING_ATTR).anyMatch(componentId::equals);
    }

    public static void addPendingFlag(GroupModel group, String componentId) {
        List<String> current = new ArrayList<>(group.getAttributeStream(PENDING_ATTR).toList());
        if (!current.contains(componentId)) {
            current.add(componentId);
            group.setAttribute(PENDING_ATTR, current);
        }
    }

    public static void removePendingFlag(GroupModel group, String componentId) {
        List<String> current = new ArrayList<>(group.getAttributeStream(PENDING_ATTR).toList());
        if (current.remove(componentId)) {
            group.setAttribute(PENDING_ATTR, current);
        }
    }

    /**
     * Returns all groups in the realm that have at least one pending componentId in
     * their PENDING_ATTR. This iterates all groups but group counts are typically orders
     * of magnitude smaller than user counts (hundreds vs. tens of thousands), so this
     * is acceptable. Unlike user attributes, Keycloak's groups API has no
     * searchForGroupByAttributeStream, so we must scan.
     */
    public static List<GroupModel> findPendingGroups(RealmModel realm) {
        return realm.getGroupsStream()
                .filter(g -> g.getAttributeStream(PENDING_ATTR).findAny().isPresent())
                .toList();
    }
}
