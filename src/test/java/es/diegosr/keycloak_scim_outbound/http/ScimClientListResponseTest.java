package es.diegosr.keycloak_scim_outbound.http;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScimClientListResponseTest {

    @Test
    void selectsTheResourceThatActuallyMatchesTheExternalId() throws Exception {
        ScimClient.ScimListResponse response = ScimClient.parseListResponse("""
                {
                  "totalResults": 2,
                  "Resources": [
                    {"id":"wrong-id","externalId":"another-user"},
                    {"id":"expected-id","externalId":"keycloak-user-id"}
                  ]
                }
                """, "externalId", "keycloak-user-id");

        assertEquals(Optional.of("expected-id"), response.matchingId());
        assertEquals(1, response.matchingResources());
        assertTrue(response.standardShape());
    }

    @Test
    void refusesAnUnrelatedResultWhenTheServerIgnoresTheFilter() throws Exception {
        ScimClient.ScimListResponse response = ScimClient.parseListResponse("""
                {
                  "totalResults": 1,
                  "Resources": [
                    {"id":"wrong-id","externalId":"another-user"}
                  ]
                }
                """, "externalId", "keycloak-user-id");

        assertTrue(response.matchingId().isEmpty());
        assertEquals(0, response.matchingResources());
    }

    @Test
    void refusesAmbiguousMatches() throws Exception {
        ScimClient.ScimListResponse response = ScimClient.parseListResponse("""
                {
                  "totalResults": 2,
                  "Resources": [
                    {"id":"first-id","externalId":"keycloak-user-id"},
                    {"id":"second-id","externalId":"keycloak-user-id"}
                  ]
                }
                """, "externalId", "keycloak-user-id");

        assertTrue(response.matchingId().isEmpty());
        assertEquals(2, response.matchingResources());
    }

    @Test
    void matchesCaseInsensitiveScimAttributesAccordingToTheirSchema() throws Exception {
        ScimClient.ScimListResponse user = ScimClient.parseListResponse("""
                {
                  "totalResults": 1,
                  "Resources": [
                    {"ID":"user-id","USERNAME":"Alice@Example.com"}
                  ]
                }
                """, "userName", "alice@example.com");
        ScimClient.ScimListResponse group = ScimClient.parseListResponse("""
                {
                  "totalResults": 1,
                  "Resources": [
                    {"id":"group-id","displayName":"Engineering"}
                  ]
                }
                """, "displayName", "engineering");

        assertEquals(Optional.of("user-id"), user.matchingId());
        assertEquals(Optional.of("group-id"), group.matchingId());
    }

    @Test
    void keepsClientIssuedExternalIdMatchingCaseSensitive() throws Exception {
        ScimClient.ScimListResponse response = ScimClient.parseListResponse("""
                {
                  "totalResults": 1,
                  "Resources": [
                    {"id":"user-id","externalId":"KEYCLOAK-ID"}
                  ]
                }
                """, "externalId", "keycloak-id");

        assertTrue(response.matchingId().isEmpty());
    }

    @Test
    void rejectsANonStandardTopLevelArray() throws Exception {
        ScimClient.ScimListResponse response = ScimClient.parseListResponse("""
                [
                  {"id":"user-id","externalId":"keycloak-user-id"}
                ]
                """, "externalId", "keycloak-user-id");

        assertTrue(response.matchingId().isEmpty());
        assertFalse(response.standardShape());
    }
}
