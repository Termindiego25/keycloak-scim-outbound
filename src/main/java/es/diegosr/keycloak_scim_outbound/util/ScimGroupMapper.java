package es.diegosr.keycloak_scim_outbound.util;

import org.keycloak.models.GroupModel;

import java.util.List;

/**
 * Builds SCIM v2 Group (urn:ietf:params:scim:schemas:core:2.0:Group) payloads.
 * All JSON escaping is delegated to ScimMapper.esc() / ScimMapper.nvl().
 */
public final class ScimGroupMapper {

    private ScimGroupMapper() {}

    /**
     * POST /Groups -- create a new SCIM Group.
     *
     * @param group   Keycloak GroupModel (provides displayName and externalId)
     * @param members resolved SCIM member references; may be empty
     */
    public static String buildCreateGroup(GroupModel group, List<ScimMemberRef> members) {
        final String displayName = ScimMapper.esc(ScimMapper.nvl(group != null ? group.getName() : ""));
        final String externalId  = ScimMapper.esc(ScimMapper.nvl(group != null ? group.getId()   : ""));

        return """
            {
              "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
              "externalId": "%s",
              "displayName": "%s",
              "members": [%s]
            }
            """.formatted(externalId, displayName, membersJson(members));
    }

    /**
     * PATCH /Groups/{id} -- replace displayName and full members list atomically.
     * Used both for renames and full re-syncs after membership changes.
     */
    public static String buildReplaceGroupPatch(String displayName, List<ScimMemberRef> members) {
        return """
            {
              "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
              "Operations": [
                {"op": "replace", "path": "displayName", "value": "%s"},
                {"op": "replace", "path": "members",     "value": [%s]}
              ]
            }
            """.formatted(ScimMapper.esc(ScimMapper.nvl(displayName)), membersJson(members));
    }

    /** PATCH to add a single member to a SCIM Group (used by real-time event path). */
    public static String buildAddMemberPatch(String scimUserId, String display) {
        return """
            {
              "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
              "Operations": [
                {"op": "add", "path": "members", "value": [{"value": "%s", "display": "%s"}]}
              ]
            }
            """.formatted(ScimMapper.esc(ScimMapper.nvl(scimUserId)),
                          ScimMapper.esc(ScimMapper.nvl(display)));
    }

    /**
     * PATCH to remove a single member from a SCIM Group by SCIM user id
     * (used by real-time event path).
     * RFC 7644 section 3.5.2.2: filter on the value sub-attribute.
     */
    public static String buildRemoveMemberPatch(String scimUserId) {
        return """
            {
              "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
              "Operations": [
                {"op": "remove", "path": "members[value eq \\"%s\\"]"}
              ]
            }
            """.formatted(ScimMapper.esc(ScimMapper.nvl(scimUserId)));
    }

    // -- helpers --------------------------------------------------------------

    private static String membersJson(List<ScimMemberRef> members) {
        if (members == null || members.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < members.size(); i++) {
            ScimMemberRef m = members.get(i);
            sb.append("{\"value\":\"").append(ScimMapper.esc(ScimMapper.nvl(m.scimId())))
              .append("\",\"display\":\"").append(ScimMapper.esc(ScimMapper.nvl(m.displayName()))).append("\"}");
            if (i < members.size() - 1) sb.append(",");
        }
        return sb.toString();
    }

    /**
     * Carries a resolved SCIM user id together with its display name, used when
     * assembling the members array of a SCIM Group payload.
     */
    public record ScimMemberRef(String scimId, String displayName) {}
}
