package es.diegosr.keycloak_scim_outbound.http;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Minimal SCIM v2 client focused on Users resource.
 */
public class ScimClient {
    private final HttpClient http;
    private final String baseUrl;
    private final String bearer;
    private final Duration requestTimeout;
    private final int maxRetries;

    // Regex robusta para sacar el primer id dentro de Resources[ {... "id":"..."} ]
    private static final Pattern RE_FIRST_ID_IN_RESOURCES = Pattern.compile(
            "\"Resources\"\\s*:\\s*\\[.*?\\{[^}]*?\"id\"\\s*:\\s*\"([^\"]+)\"",
            Pattern.DOTALL
    );
    // Regex para UUID (v4 típico) por si el servidor lo incluye entre `backticks`
    private static final Pattern RE_UUID_IN_BACKTICKS = Pattern.compile("`([0-9a-fA-F\\-]{36})`");

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
        try {
            String filter = String.format("userName eq \"%s\"", userName);
            String query = "filter=" + urlEncode(filter);
            HttpRequest req = baseRequestBuilder("/Users?" + query).GET().build();

            HttpResponse<String> res = sendWithRetries(req);
            if (is2xx(res.statusCode())) {
                String body = res.body();
                int total = JsonMini.totalResults(body);
                httpInfo("GET /Users?%s -> %d totalResults=%d", query, res.statusCode(), total);
                if (total > 0) {
                    // Regex robusta dentro de Resources
                    Matcher m = RE_FIRST_ID_IN_RESOURCES.matcher(body);
                    if (m.find()) {
                        return Optional.ofNullable(m.group(1));
                    } else {
                        httpErr("Could not extract user id from SCIM response (Resources present but no id found).");
                    }
                }
            } else {
                httpErr("GET /Users?%s -> %d %s", query, res.statusCode(), safeBody(res));
            }
        } catch (Exception e) {
            httpErr("findUserIdByUserName failed: %s", e.getMessage());
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

            HttpResponse<String> res = sendWithRetries(req);
            if (res.statusCode() == 201 || res.statusCode() == 200) return true;

            if (res.statusCode() == 409) {
                // Diagnóstico: intenta extraer un UUID real de los backticks
                String existingId = JsonMini.extractUuidFromError(res.body());
                httpInfo("POST /Users got 409; existingId=%s", existingId != null ? existingId : "(not parsed)");
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
        return sendJson("PATCH", "/Users/" + id, jsonPatch, 200, 204);
    }

    public boolean deleteUser(String id) {
        try {
            HttpRequest req = baseRequestBuilder("/Users/" + id).DELETE().build();
            HttpResponse<String> res = sendWithRetries(req);
            boolean ok = res.statusCode() == 204 || res.statusCode() == 200 || res.statusCode() == 404;
            if (!ok) httpErr("DELETE /Users/%s -> %d %s", id, res.statusCode(), safeBody(res));
            return ok;
        } catch (Exception e) {
            httpErr("DELETE /Users/%s failed: %s", id, e.getMessage());
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
    private static String urlEncode(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8); }
    private static void sleep(long ms) { try { Thread.sleep(ms); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); } }
    private static String safeBody(HttpResponse<String> res) { String b = res.body(); return b == null ? "" : (b.length() > 400 ? b.substring(0, 400) + " …" : b); }

    /* ===== timestamped logging (stdout/stderr) ===== */
    private static String now() { return java.time.OffsetDateTime.now().toString(); }
    private static void httpInfo(String fmt, Object... args) { System.out.printf("%s [keycloak-scim-outbound/HTTP] %s%n", now(), String.format(fmt, args)); }
    private static void httpErr(String fmt, Object... args)  { System.err.printf("%s [keycloak-scim-outbound/HTTP] %s%n", now(), String.format(fmt, args)); }

    /** Tiny helpers */
    static class JsonMini {
        static int totalResults(String body) {
            if (body == null) return 0;
            int t = body.indexOf("\"totalResults\"");
            if (t < 0) return 0;
            int colon = body.indexOf(':', t);
            if (colon < 0) return 0;
            int end = colon + 1;
            StringBuilder sb = new StringBuilder();
            while (end < body.length()) {
                char c = body.charAt(end++);
                if (Character.isDigit(c)) sb.append(c);
                else if (sb.length() > 0) break;
            }
            try { return Integer.parseInt(sb.toString()); } catch (Exception ignored) { return 0; }
        }

        static String extractUuidFromError(String body) {
            if (body == null) return null;
            Matcher m = RE_UUID_IN_BACKTICKS.matcher(body);
            return m.find() ? m.group(1) : null;
        }
    }
}