package uk.gov.moj.cpp.authz.http;

import java.util.Set;
import java.util.UUID;

public record AuthzPrincipal(
        UUID userId,
        String firstName,
        String lastName,
        String email,
        Set<String> groups
) {
}