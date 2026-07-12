package es.diegosr.keycloak_scim_outbound.http;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Minimal SCIM v2 HTTP client (Users + Groups).
 * All logging goes through the JBoss/Keycloak logger and respects the
 * configured log-level category. No direct stdout/stderr writes.
 */
public class ScimClient {

    private static final Logger LOG = Logger.getLogger(ScimClient.class);

    private final HttpClient http;
    private final String baseUrl;
    private final String bearer;
    private final Duration requestTimeout;
    private final int maxRetries;

    private static final ObjectMapper JSON = new ObjectMapper();

    public ScimClient(String baseUrl, String bearer) {
        this(baseUrl, bearer, Duration.ofSeconds(8), 3);
    }

    public ScimClient(String baseUrl, String bearer, Duration timeout, int maxRetries) {
        this.baseUrl        = trimTrailingSlash(baseUrl);
        this.bearer         = bearer;
        this.requestTimeout = timeout != null ? timeout : Duration.ofSeconds(8);
        this.maxRetries     = Math.max(0, maxRetries);
        this.http           = HttpClient.newBuilder()
                .connectTimeout(this.requestTimeout)
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    public boolean smokeTest() {
        try {
            HttpRequest req = baseRequestBuilder("/ServiceProviderConfig").GET().build();
            LOG.debugf("GET /ServiceProviderConfig (smokeTest) bearerPresent=%s",
                    bearer != null && !bearer.isBlank());
            HttpResponse<String> res = sendWithRetries(req);
            LOG.debugf("GET /ServiceProviderConfig (smokeTest) status=%d body=%s",
                    res.statusCode(), res.body());
            return is2xx(res.statusCode());
        } catch (Exception e) {
            LOG.errorf("smokeTest failed: %s", e.getMessage());
            return false;
        }
    }

    // =========================================================================
    // Users
    // =========================================================================

    /** Find user by userName and return the SCIM id if present. */
    public Optional<String> findUserIdByUserName(String userName) {
        return findUserIdByFilter("userName", userName, "findUserIdByUserName");
    }

    /**
     * Find user by externalId and return the SCIM id if present.
     *
     * Some SCIM servers ignore the externalId filter and return all users
     * (totalResults > 1). Picking resources[0] in that case would silently
     * return the wrong user for every call. We therefore treat totalResults != 1
     * as a miss so the caller can fall through to a userName-based lookup.
     * Servers that honour the filter still get a correct single-result fast path.
     */
    public Optional<String> findUserIdByExternalId(String externalId) {
        if (externalId == null || externalId.isBlank()) return Optional.empty();

        try {
            String filter = "externalId eq " + scimFilterString(externalId);
            String query  = "filter=" + urlEncode(filter);
            HttpRequest req = baseRequestBuilder("/Users?" + query).GET().build();

            LOG.debugf("findUserIdByExternalId GET /Users?%s", query);
            HttpResponse<String> res = sendWithRetries(req);
            LOG.debugf("findUserIdByExternalId status=%d body=%s", res.statusCode(), res.body());

            if (is2xx(res.statusCode())) {
                ScimListResponse users = parseListResponse(res.body());
                LOG.infof("GET /Users?%s -> %d totalResults=%d", query, res.statusCode(), users.totalResults());

                if (users.totalResults() == 1 && users.firstId().isPresent()) {
                    return users.firstId();
                }
                if (users.totalResults() > 1) {
                    LOG.infof("findUserIdByExternalId: totalResults=%d for externalId=%s -- "
                            + "server likely ignores externalId filter; treating as miss",
                            users.totalResults(), externalId);
                }
            } else {
                LOG.errorf("GET /Users?%s -> %d %s", query, res.statusCode(), safeBody(res));
            }
        } catch (Exception e) {
            LOG.errorf("findUserIdByExternalId failed: %s", e.getMessage());
        }
        return Optional.empty();
    }

    private Optional<String> findUserIdByFilter(String attribute, String value, String operation) {
        if (value == null || value.isBlank()) return Optional.empty();

        try {
            String filter = attribute + " eq " + scimFilterString(value);
            String query  = "filter=" + urlEncode(filter);
            HttpRequest req = baseRequestBuilder("/Users?" + query).GET().build();

            LOG.debugf("%s GET /Users?%s", operation, query);
            HttpResponse<String> res = sendWithRetries(req);
            LOG.debugf("%s status=%d body=%s", operation, res.statusCode(), res.body());

            if (is2xx(res.statusCode())) {
                ScimListResponse users = parseListResponse(res.body());
                LOG.infof("GET /Users?%s -> %d totalResults=%d", query, res.statusCode(), users.totalResults());
                if (users.firstId().isPresent()) {
                    return users.firstId();
                }
                if (users.totalResults() > 0 || users.resourcesPresent()) {
                    LOG.errorf("Could not extract user id from SCIM response (resources present but no id)");
                }
            } else {
                LOG.errorf("GET /Users?%s -> %d %s", query, res.statusCode(), safeBody(res));
            }
        } catch (Exception e) {
            LOG.errorf("%s failed: %s", operation, e.getMessage());
        }
        return Optional.empty();
    }

    /** Create SCIM user; returns true on 201/200. */
    public boolean createUser(String jsonPayload) {
        try {
            HttpRequest req = baseRequestBuilder("/Users")
                    .header("Content-Type", "application/scim+json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .build();

            LOG.debugf("POST /Users body=%s", jsonPayload);
            HttpResponse<String> res = sendWithRetries(req);
            LOG.debugf("POST /Users status=%d body=%s", res.statusCode(), res.body());

            if (res.statusCode() == 201 || res.statusCode() == 200) return true;
            if (res.statusCode() == 409) {
                LOG.infof("POST /Users 409 conflict: %s", safeBody(res));
            } else {
                LOG.errorf("POST /Users -> %d %s", res.statusCode(), safeBody(res));
            }
            return false;
        } catch (Exception e) {
            LOG.errorf("POST /Users failed: %s", e.getMessage());
            return false;
        }
    }

    /** Patch SCIM user by id (RFC 7644 PatchOp). */
    public boolean patchUser(String id, String jsonPatch) {
        return sendJson("PATCH", userPath(id), jsonPatch, 200, 204);
    }

    /** Delete SCIM user by id. */
    public boolean deleteUser(String id) {
        String path = userPath(id);
        try {
            HttpRequest req = baseRequestBuilder(path).DELETE().build();
            LOG.debugf("DELETE %s", path);
            HttpResponse<String> res = sendWithRetries(req);
            LOG.debugf("DELETE %s status=%d body=%s", path, res.statusCode(), res.body());
            boolean ok = res.statusCode() == 204 || res.statusCode() == 200 || res.statusCode() == 404;
            if (!ok) LOG.errorf("DELETE %s -> %d %s", path, res.statusCode(), safeBody(res));
            return ok;
        } catch (Exception e) {
            LOG.errorf("DELETE %s failed: %s", path, e.getMessage());
            return false;
        }
    }

    // =========================================================================
    // Groups
    // =========================================================================

    /** Find group by displayName and return the SCIM id if present. */
    public Optional<String> findGroupIdByDisplayName(String displayName) {
        return findGroupIdByFilter("displayName", displayName, "findGroupIdByDisplayName");
    }

    /** Find group by externalId and return the SCIM id if present. */
    public Optional<String> findGroupIdByExternalId(String externalId) {
        return findGroupIdByFilter("externalId", externalId, "findGroupIdByExternalId");
    }

    /**
     * Find group by externalId and return both the id and the raw totalResults count.
     *
     * Callers that need to distinguish "not found" from "ambiguous" (totalResults > 1)
     * should use this method instead of findGroupIdByExternalId. A UUID-based externalId
     * should always yield exactly one result; more than one indicates a server-side data
     * issue and the caller should fall back to a displayName lookup rather than picking
     * an arbitrary match.
     */
    public ScimLookupResult findGroupByExternalId(String externalId) {
        if (externalId == null || externalId.isBlank()) {
            return new ScimLookupResult(Optional.empty(), 0);
        }
        try {
            String filter = "externalId eq " + scimFilterString(externalId);
            String query  = "filter=" + urlEncode(filter);
            HttpRequest req = baseRequestBuilder("/Groups?" + query).GET().build();

            LOG.debugf("findGroupByExternalId GET /Groups?%s", query);
            HttpResponse<String> res = sendWithRetries(req);
            LOG.debugf("findGroupByExternalId status=%d body=%s", res.statusCode(), res.body());

            if (is2xx(res.statusCode())) {
                ScimListResponse groups = parseListResponse(res.body());
                LOG.infof("GET /Groups?%s -> %d totalResults=%d", query, res.statusCode(), groups.totalResults());
                // Only return the id when exactly one result is found; multiple results
                // are ambiguous and the caller must fall back to a displayName lookup.
                if (groups.totalResults() == 1 && groups.firstId().isPresent()) {
                    return new ScimLookupResult(groups.firstId(), 1);
                }
                return new ScimLookupResult(Optional.empty(), groups.totalResults());
            } else {
                LOG.errorf("GET /Groups?%s -> %d %s", query, res.statusCode(), safeBody(res));
            }
        } catch (Exception e) {
            LOG.errorf("findGroupByExternalId failed: %s", e.getMessage());
        }
        return new ScimLookupResult(Optional.empty(), 0);
    }

    /** Result type for group lookups that need to expose totalResults alongside the id. */
    public record ScimLookupResult(Optional<String> id, int totalResults) {}

    private Optional<String> findGroupIdByFilter(String attribute, String value, String operation) {
        if (value == null || value.isBlank()) return Optional.empty();
        try {
            String filter = attribute + " eq " + scimFilterString(value);
            String query  = "filter=" + urlEncode(filter);
            HttpRequest req = baseRequestBuilder("/Groups?" + query).GET().build();

            LOG.debugf("%s GET /Groups?%s", operation, query);
            HttpResponse<String> res = sendWithRetries(req);
            LOG.debugf("%s status=%d body=%s", operation, res.statusCode(), res.body());

            if (is2xx(res.statusCode())) {
                ScimListResponse groups = parseListResponse(res.body());
                LOG.infof("GET /Groups?%s -> %d totalResults=%d", query, res.statusCode(), groups.totalResults());
                return groups.firstId();
            } else {
                LOG.errorf("GET /Groups?%s -> %d %s", query, res.statusCode(), safeBody(res));
            }
        } catch (Exception e) {
            LOG.errorf("%s failed: %s", operation, e.getMessage());
        }
        return Optional.empty();
    }

    /**
     * Returns the list of SCIM user IDs that are members of the given SCIM group.
     * Fetches the group directly by SCIM id (GET /Groups/{id}) and extracts the
     * "members" array. A missing or empty members array is treated as an empty list
     * and is not an error. Used by the cross-check in ScimGroupSync.
     */
    public List<String> getGroupMembers(String scimGroupId) {
        if (scimGroupId == null || scimGroupId.isBlank()) return List.of();
        String path = groupPath(scimGroupId);
        try {
            HttpRequest req = baseRequestBuilder(path).GET().build();
            LOG.debugf("getGroupMembers GET %s", path);
            HttpResponse<String> res = sendWithRetries(req);
            LOG.debugf("getGroupMembers status=%d", res.statusCode());

            if (!is2xx(res.statusCode())) {
                LOG.errorf("GET %s -> %d %s", path, res.statusCode(), safeBody(res));
                return List.of();
            }
            String body = res.body();
            if (body == null || body.isBlank()) return List.of();

            JsonNode root = JSON.readTree(body);
            // RFC 7643 s4.2 specifies "members" (lowercase). Some servers capitalise.
            JsonNode members = root.path("members");
            if (!members.isArray() || members.isEmpty()) {
                members = root.path("Members");
            }
            if (!members.isArray() || members.isEmpty()) {
                LOG.debugf("getGroupMembers: no members array for scimGroupId=%s", scimGroupId);
                return List.of();
            }

            List<String> ids = new ArrayList<>();
            for (JsonNode member : members) {
                JsonNode val = member.path("value");
                if (val.isTextual() && !val.asText().isBlank()) {
                    ids.add(val.asText());
                }
            }
            LOG.debugf("getGroupMembers: scimGroupId=%s -> %d member(s)", scimGroupId, ids.size());
            return ids;
        } catch (Exception e) {
            LOG.errorf("getGroupMembers failed for scimGroupId=%s: %s", scimGroupId, e.getMessage());
            return List.of();
        }
    }

    /** Create SCIM group; returns true on 201/200. */
    public boolean createGroup(String jsonPayload) {
        try {
            HttpRequest req = baseRequestBuilder("/Groups")
                    .header("Content-Type", "application/scim+json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .build();

            LOG.debugf("POST /Groups body=%s", jsonPayload);
            HttpResponse<String> res = sendWithRetries(req);
            LOG.debugf("POST /Groups status=%d body=%s", res.statusCode(), res.body());

            if (res.statusCode() == 201 || res.statusCode() == 200) return true;
            if (res.statusCode() == 409) {
                LOG.infof("POST /Groups 409 conflict: %s", safeBody(res));
            } else {
                LOG.errorf("POST /Groups -> %d %s", res.statusCode(), safeBody(res));
            }
            return false;
        } catch (Exception e) {
            LOG.errorf("POST /Groups failed: %s", e.getMessage());
            return false;
        }
    }

    /** Patch SCIM group by id (RFC 7644 PatchOp). */
    public boolean patchGroup(String id, String jsonPatch) {
        return sendJson("PATCH", groupPath(id), jsonPatch, 200, 204);
    }

    /** Delete SCIM group by id. */
    public boolean deleteGroup(String id) {
        String path = groupPath(id);
        try {
            HttpRequest req = baseRequestBuilder(path).DELETE().build();
            LOG.debugf("DELETE %s", path);
            HttpResponse<String> res = sendWithRetries(req);
            LOG.debugf("DELETE %s status=%d body=%s", path, res.statusCode(), res.body());
            boolean ok = res.statusCode() == 204 || res.statusCode() == 200 || res.statusCode() == 404;
            if (!ok) LOG.errorf("DELETE %s -> %d %s", path, res.statusCode(), safeBody(res));
            return ok;
        } catch (Exception e) {
            LOG.errorf("DELETE %s failed: %s", path, e.getMessage());
            return false;
        }
    }

    // =========================================================================
    // Internals
    // =========================================================================

    private boolean sendJson(String method, String path, String json, int... okCodes) {
        try {
            HttpRequest req = baseRequestBuilder(path)
                    .header("Content-Type", "application/scim+json")
                    .method(method, HttpRequest.BodyPublishers.ofString(json))
                    .build();

            LOG.debugf("%s %s body=%s", method, path, json);
            HttpResponse<String> res = sendWithRetries(req);
            LOG.debugf("%s %s status=%d body=%s", method, path, res.statusCode(), res.body());

            if (matches(res.statusCode(), okCodes)) return true;
            LOG.errorf("%s %s -> %d %s", method, path, res.statusCode(), safeBody(res));
            return false;
        } catch (Exception e) {
            LOG.errorf("%s %s failed: %s", method, path, e.getMessage());
            return false;
        }
    }

    private HttpRequest.Builder baseRequestBuilder(String pathOrQuery) {
        String url = this.baseUrl + (pathOrQuery.startsWith("/") ? pathOrQuery : "/" + pathOrQuery);
        return HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(this.requestTimeout)
                .header("Authorization", "Bearer " + bearer)
                .header("Accept", "application/scim+json")
                .header("User-Agent", "keycloak-scim-outbound/1.0");
    }

    private HttpResponse<String> sendWithRetries(HttpRequest req) throws Exception {
        int attempt = 0;
        long backoff = 250L;
        while (true) {
            attempt++;
            HttpResponse<String> res;
            try {
                res = http.send(req, HttpResponse.BodyHandlers.ofString());
            } catch (Exception e) {
                LOG.debugf("Attempt %d for %s %s threw %s", attempt, req.method(), req.uri(), e.getMessage());
                if (attempt > this.maxRetries) throw e;
                sleep(backoff);
                backoff = Math.min(backoff * 2, 2000L);
                continue;
            }

            int sc = res.statusCode();
            if (is2xx(sc)) return res;

            if ((sc == 429 || (sc >= 500 && sc <= 599)) && attempt <= this.maxRetries) {
                LOG.debugf("Attempt %d for %s %s got retryable status=%d, backing off %dms",
                        attempt, req.method(), req.uri(), sc, backoff);
                sleep(backoff);
                backoff = Math.min(backoff * 2, 2000L);
                continue;
            }
            return res;
        }
    }

    private static ScimListResponse parseListResponse(String body) throws Exception {
        if (body == null || body.isBlank()) {
            return new ScimListResponse(0, Optional.empty(), false);
        }
        JsonNode root = JSON.readTree(body);
        int totalResults = root.path("totalResults").asInt(0);

        // RFC 7643 specifies "Resources" (capital R), but some implementations use lowercase.
        JsonNode resources = root.path("Resources");
        if (!resources.isArray() || resources.isEmpty()) {
            resources = root.path("resources");
        }
        boolean resourcesPresent = resources.isArray() && !resources.isEmpty();
        if (!resourcesPresent) {
            return new ScimListResponse(totalResults, Optional.empty(), false);
        }
        JsonNode id = resources.get(0).path("id");
        if (id.isTextual() && !id.asText().isBlank()) {
            return new ScimListResponse(totalResults, Optional.of(id.asText()), true);
        }
        return new ScimListResponse(totalResults, Optional.empty(), true);
    }

    private static boolean is2xx(int code) { return code >= 200 && code < 300; }
    private static boolean matches(int code, int... ok) { for (int c : ok) if (c == code) return true; return false; }
    private static String trimTrailingSlash(String s) { if (s == null || s.isEmpty()) return s; return s.endsWith("/") ? s.substring(0, s.length() - 1) : s; }
    private static String userPath(String id)  { return "/Users/"  + urlEncode(id); }
    private static String groupPath(String id) { return "/Groups/" + urlEncode(id); }
    private static String urlEncode(String s)  { return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20"); }
    private static void sleep(long ms) { try { Thread.sleep(ms); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); } }
    private static String safeBody(HttpResponse<String> res) { String b = res.body(); return b == null ? "" : (b.length() > 400 ? b.substring(0, 400) + " ..." : b); }
    private static String scimFilterString(String v) { return "\"" + jsonEscape(v) + "\""; }

    private static String jsonEscape(String s) {
        StringBuilder out = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"'  -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> { if (c < 0x20) out.append(String.format("\\u%04x", (int) c)); else out.append(c); }
            }
        }
        return out.toString();
    }

    private record ScimListResponse(int totalResults, Optional<String> firstId, boolean resourcesPresent) {}
}
