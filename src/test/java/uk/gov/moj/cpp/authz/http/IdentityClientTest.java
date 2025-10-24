package uk.gov.moj.cpp.authz.http;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class IdentityClientTest {

    @InjectMocks
    IdentityClient identityClient;

    @Test
    void properties_url_should_accept_valid_url() {
        identityClient.constructUrl("http://localhost", "/path");
        identityClient.constructUrl("http://localhost:8080", "/usersgroups-query-api/query/api/rest/usersgroups/users/logged-in-user/permissions");
        // no exception
    }

    @Test
    void properties_url_should_error_when_bad_url() {
        assertThrows(RuntimeException.class, () -> identityClient.constructUrl("this--bad-url", "path"));
        assertThrows(RuntimeException.class, () -> identityClient.constructUrl("http://localhost-%%$^&& iuyi", "path"));
    }
}