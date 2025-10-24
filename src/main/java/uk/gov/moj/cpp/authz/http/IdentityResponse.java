package uk.gov.moj.cpp.authz.http;

import uk.gov.moj.cpp.authz.http.dto.UserGroup;
import uk.gov.moj.cpp.authz.http.dto.UserPermission;

import java.util.List;
import java.util.UUID;

public record IdentityResponse(
        UUID userId,
        List<UserGroup> groups,
        List<UserPermission> permissions
) {
}