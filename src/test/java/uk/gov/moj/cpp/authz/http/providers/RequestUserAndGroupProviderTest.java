package uk.gov.moj.cpp.authz.http.providers;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import uk.gov.moj.cpp.authz.drools.Action;
import uk.gov.moj.cpp.authz.http.AuthzPrincipal;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

class RequestUserAndGroupProviderTest {

    UUID userId = UUID.randomUUID();

    @Test
    void returnsTrueWhenPrincipalHasAnyOfTheGroups() {
        final AuthzPrincipal principal = new AuthzPrincipal(userId, "fn", "ln", "u1@example.test", Set.of("Legal Advisers", "Other"));
        final RequestUserAndGroupProvider provider = new RequestUserAndGroupProvider(principal);
        final Action action = new Action("GET /api/hello", Map.of());

        final boolean result = provider.isMemberOfAnyOfTheSuppliedGroups(action,
                "Prosecuting Authority Access", "Legal Advisers");

        Assertions.assertTrue(result, "Expected match when principal has one of the groups");
    }

    @Test
    void returnsFalseWhenPrincipalLacksGroups() {
        final AuthzPrincipal principal = new AuthzPrincipal(
                userId, "fn", "ln", "u2@example.test", Set.of("Guests"));
        final RequestUserAndGroupProvider provider = new RequestUserAndGroupProvider(principal);
        final Action action = new Action("GET /api/hello", Map.of());

        final boolean result = provider.isMemberOfAnyOfTheSuppliedGroups(action,
                "Legal Advisers", "Prosecuting Authority Access");

        Assertions.assertFalse(result, "Expected no match when principal lacks groups");
    }

    @Test
    void returnsFalseWhenPrincipalIsNull() {
        final RequestUserAndGroupProvider provider = new RequestUserAndGroupProvider(null);
        final Action action = new Action("GET /api/hello", Map.of());

        final boolean result = provider.isMemberOfAnyOfTheSuppliedGroups(action, "Anything");

        Assertions.assertFalse(result, "Expected false when principal is null");
    }
}
