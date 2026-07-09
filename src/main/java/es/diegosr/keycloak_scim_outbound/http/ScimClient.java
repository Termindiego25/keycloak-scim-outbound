package es.diegosr.keycloak_scim_outbound.http;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;

/**
 * Minimal SCIM v2 client focused on Users resource.
 */
public class ScimClient {
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
        this.baseUrl = trimTrailingSlash(baseUrl);
        this.bearer = bearer;
        this.requestTimeout = timeout != null ? timeout : Duration.ofSeconds(8);
        this.maxRetries = Math.max(0, maxRetries);
        this.http = HttpClient.newBuilder()
                .connectTimeout(this.requestTimeout)
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    public boolean smokeTest() {
        try {
            HttpRequest req = baseRequestBuilder("/ServiceProviderConfig").GET().build();
            HttpResponse<String> res = sendWithRetries(req);
            return is2xx(res.statusCode());
        } catch (Exception e) {
            httpErr("smokeTest failed: %s", e.getMessage());
            return false;
        }
    }

    /** Find user by userName and return SCIM id if present. */
    public Optional<String> findUserIdByUserName(String userName) {
        return findUserIdByFilter("userName", userName, "findUserIdByUserName");
    }

    /** Find user by externalId and return SCIM id if present. */
    public Optional<String> findUserIdByExternalId(String externalId) {
        return findUserIdByFilter("externalId", externalId, "findUserIdByExternalId");
    }

    private Optional<String> findUserIdByFilter(String attribute, String value, String operation) {
        if (value == null || value.isBlank()) return Optional.empty();

        try {
            String filter = attribute + " eq " + scimFilterString(value);
            String query = "filter=" + urlEncode(filter);
            HttpRequest req = baseRequestBuilder("/Users?" + query).GET().build();

            HttpResponse<String> res = sendWithRetries(req);
            if (is2xx(res.statusCode())) {
                String body = res.body();
                ScimListResponse users = parseListResponse(body);
                httpInfo("GET /Users?%s -> %d totalResults=%d", query, res.statusCode(), users.totalResults());
                if (users.firstId().isPresent()) {
                    return users.firstId();
                }
                if (users.totalResults() > 0 || users.resourcesPresent()) {
                    httpErr("Could not extract user id from SCIM response (Resources present but no id found).");
                }
            } else {
                httpErr("GET /Users?%s -> %d %s", query, res.statusCode(), safeBody(res));
            }
        } catch (Exception e) {
            httpErr("%s failed: %s", operation, e.getMessage());
        }
        return Optional.empty();
    }

    private static ScimListResponse parseListResponse(String body) throws Exception {
        if (body == null || body.isBlank()) {
            return new ScimListResponse(0, Optional.empty(), false);
        }

        JsonNode root = JSON.readTree(body);
        int totalResults = root.path("totalResults").asInt(0);
        JsonNode resources = root.path("Resources");
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

    /** Create SCIM user; returns true on 201/200. */
    public boolean createUser(String jsonPayload) {
        try {
            HttpRequest req = baseRequestBuilder("/Users")
                    .header("Content-Type", "application/scim+json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .build();

            HttpResponse<String> res = sendWithRetries(req);
            if (res.statusCode() == 201 || res.statusCode() == 200) return true;

            if (res.statusCode() == 409) {
                httpInfo("POST /Users got 409 conflict: %s", safeBody(res));
            } else {
                httpErr("POST /Users -> %d %s", res.statusCode(), safeBody(res));
            }
            return false;
        } catch (Exception e) {
            httpErr("POST /Users failed: %s", e.getMessage());
            return false;
        }
    }

    /** Patch SCIM user by id (RFC 7644 PatchOp). */
    public boolean patchUser(String id, String jsonPatch) {
        return sendJson("PATCH", userPath(id), jsonPatch, 200, 204);
    }

    public boolean deleteUser(String id) {
        String path = userPath(id);
        try {
            HttpRequest req = baseRequestBuilder(path).DELETE().build();
            HttpResponse<String> res = sendWithRetries(req);
            boolean ok = res.statusCode() == 204 || res.statusCode() == 200 || res.statusCode() == 404;
            if (!ok) httpErr("DELETE %s -> %d %s", path, res.statusCode(), safeBody(res));
            return ok;
        } catch (Exception e) {
            httpErr("DELETE %s failed: %s", path, e.getMessage());
            return false;
        }
    }

    /* ======================= Groups ======================= */

    /** Find group by displayName and return SCIM id if present. */
    public Optional<String> findGroupIdByDisplayName(String displayName) {
        return findGroupIdByFilter("displayName", displayName, "findGroupIdByDisplayName");
    }

    /** Find group by externalId and return SCIM id if present. */
    public Optional<String> findGroupIdByExternalId(String externalId) {
        return findGroupIdByFilter("externalId", externalId, "findGroupIdByExternalId");
    }

    private Optional<String> findGroupIdByFilter(String attribute, String value, String operation) {
        if (value == null || value.isBlank()) return Optional.empty();
        try {
            String filter = attribute + " eq " + scimFilterString(value);
            String query = "filter=" + urlEncode(filter);
            HttpRequest req = baseRequestBuilder("/Groups?" + query).GET().build();
            HttpResponse<String> res = sendWithRetries(req);
            if (is2xx(res.statusCode())) {
                ScimListResponse groups = parseListResponse(res.body());
                httpInfo("GET /Groups?%s -> %d totalResults=%d", query, res.statusCode(), groups.totalResults());
                return groups.firstId();
            } else {
                httpErr("GET /Groups?%s -> %d %s", query, res.statusCode(), safeBody(res));
            }
        } catch (Exception e) {
            httpErr("%s failed: %s", operation, e.getMessage());
        }
        return Optional.empty();
    }

    /** Create SCIM group; returns true on 201/200. */
    public boolean createGroup(String jsonPayload) {
        try {
            HttpRequest req = baseRequestBuilder("/Groups")
                    .header("Content-Type", "application/scim+json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .build();
            HttpResponse<String> res = sendWithRetries(req);
            if (res.statusCode() == 201 || res.statusCode() == 200) return true;
            if (res.statusCode() == 409) {
                httpInfo("POST /Groups got 409 conflict: %s", safeBody(res));
            } else {
                httpErr("POST /Groups -> %d %s", res.statusCode(), safeBody(res));
            }
            return false;
        } catch (Exception e) {
            httpErr("POST /Groups failed: %s", e.getMessage());
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
            HttpResponse<String> res = sendWithRetries(req);
            boolean ok = res.statusCode() == 204 || res.statusCode() == 200 || res.statusCode() == 404;
            if (!ok) httpErr("DELETE %s -> %d %s", path, res.statusCode(), safeBody(res));
            return ok;
        } catch (Exception e) {
            httpErr("DELETE %s failed: %s", path, e.getMessage());
            return false;
        }
    }

    /* ======================= internals ======================= */

    private boolean sendJson(String method, String path, String json, int... okCodes) {
        try {
            HttpRequest.BodyPublisher body = HttpRequest.BodyPublishers.ofString(json);
            HttpRequest.Builder b = baseRequestBuilder(path)
                    .header("Content-Type", "application/scim+json")
                    .method(method, body);

            HttpResponse<String> res = sendWithRetries(b.build());
            if (matches(res.statusCode(), okCodes)) return true;

            httpErr("%s %s -> %d %s", method, path, res.statusCode(), safeBody(res));
            return false;
        } catch (Exception e) {
            httpErr("%s %s failed: %s", method, path, e.getMessage());
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
                if (attempt > this.maxRetries) throw e;
                sleep(backoff);
                backoff = Math.min(backoff * 2, 2000L);
                continue;
            }

            int sc = res.statusCode();
            if (is2xx(sc)) return res;

            if ((sc == 429 || (sc >= 500 && sc <= 599)) && attempt <= this.maxRetries) {
                sleep(backoff);
                backoff = Math.min(backoff * 2, 2000L);
                continue;
            }
            return res;
        }
    }

    private static boolean is2xx(int code) { return code >= 200 && code < 300; }
    private static boolean matches(int code, int... okCodes) { for (int ok : okCodes) if (ok == code) return true; return false; }
    private static String trimTrailingSlash(String s) { if (s == null || s.isEmpty()) return s; return s.endsWith("/") ? s.substring(0, s.length() - 1) : s; }
    private static String userPath(String id)  { return "/Users/"  + urlEncode(id); }
    private static String groupPath(String id) { return "/Groups/" + urlEncode(id); }
    private static String urlEncode(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20"); }
    private static void sleep(long ms) { try { Thread.sleep(ms); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); } }
    private static String safeBody(HttpResponse<String> res) { String b = res.body(); return b == null ? "" : (b.length() > 400 ? b.substring(0, 400) + " …" : b); }

    private static String scimFilterString(String value) { return "\"" + jsonEscape(value) + "\""; }
    private static String jsonEscape(String s) {
        StringBuilder out = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }

    /* ===== timestamped logging (stdout/stderr) ===== */
    private static String now() { return java.time.OffsetDateTime.now().toString(); }
    private static void httpInfo(String fmt, Object... args) { System.out.printf("%s [keycloak-scim-outbound/HTTP] %s%n", now(), String.format(fmt, args)); }
    private static void httpErr(String fmt, Object... args)  { System.err.printf("%s [keycloak-scim-outbound/HTTP] %s%n", now(), String.format(fmt, args)); }

    private record ScimListResponse(int totalResults, Optional<String> firstId, boolean resourcesPresent) {}
}
