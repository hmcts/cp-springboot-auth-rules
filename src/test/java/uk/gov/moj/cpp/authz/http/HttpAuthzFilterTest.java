package uk.gov.moj.cpp.authz.http;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import uk.gov.moj.cpp.authz.drools.Action;
import uk.gov.moj.cpp.authz.drools.DroolsAuthzEngine;
import uk.gov.moj.cpp.authz.http.config.HttpAuthzProperties;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class HttpAuthzFilterTest {

    private static final String USER_ID_HEADER = "CJSCPPUID";
    private static final String ACTION_HEADER = "CPP-ACTION";
    private static final String METHOD_GET = "GET";
    private static final String METHOD_POST = "POST";
    private static final String PATH_HELLO = "/api/hello";
    private static final String PATH_ECHO = "/api/echo";
    private static final String PATH_EXCLUDED = "/usersgroups-query-api/query/api/rest/ping";
    private static final String PATH_EXCLUDED_METRICS = "/metrics/prometheus";
    private static final UUID USER_ID = UUID.fromString("a05078bd-b189-4fd9-8c6e-181e9a123456");
    private static final UUID USER_ID_UC = UUID.fromString("E3F58BF7-FB59-4E5C-8ED9-E6A0F5966743");
    private static final String ACTION_GET_HELLO = "GET /api/hello";
    private static final String ACTION_POST_ECHO = "POST /api/echo";
    private static final String GROUP_LEGAL_ADVISERS = "Legal Advisers";

    @Mock
    private IdentityClient identityClient;

    @Mock
    private IdentityToGroupsMapper identityToGroupsMapper;

    @Mock
    private DroolsAuthzEngine droolsAuthzEngine;

    @Mock
    private FilterChain filterChain;

    private HttpAuthzProperties httpAuthzProperties;
    private HttpAuthzFilter httpAuthzFilter;

    @BeforeEach
    void setUp() {
        httpAuthzProperties = new HttpAuthzProperties();
        httpAuthzProperties.setEnabled(true);
        httpAuthzProperties.setUserIdHeader(USER_ID_HEADER);
        httpAuthzProperties.setActionHeader(ACTION_HEADER);
        httpAuthzProperties.setAcceptHeader("application/vnd.usersgroups.get-logged-in-user-permissions+json");
        httpAuthzProperties.setDroolsClasspathPattern("classpath*:/uk/gov/moj/cpp/authz/demo/*.drl");
        httpAuthzProperties.setReloadOnEachRequest(false);
        httpAuthzProperties.setActionRequired(false);
        httpAuthzProperties.setDenyWhenNoRules(true);
        httpAuthzProperties.setExcludePathPrefixes(List.of("/usersgroups-query-api/", "/actuator/"));

        httpAuthzFilter = new HttpAuthzFilter(
                httpAuthzProperties, identityClient, identityToGroupsMapper, droolsAuthzEngine);
    }

    @Test
    void forwardsRequestUnchangedWhenPathIsExcluded() throws Exception {
        final MockHttpServletRequest req = new MockHttpServletRequest(METHOD_GET, PATH_EXCLUDED);
        final MockHttpServletResponse res = new MockHttpServletResponse();

        httpAuthzFilter.doFilter(req, res, filterChain);

        verify(filterChain, times(1)).doFilter(req, res);
    }

    @Test
    void returns401WhenUserIdHeaderIsMissing() throws Exception {
        final MockHttpServletRequest req = new MockHttpServletRequest(METHOD_GET, PATH_HELLO);
        final MockHttpServletResponse res = new MockHttpServletResponse();

        httpAuthzFilter.doFilter(req, res, filterChain);

        assertEquals(401, res.getStatus(), "Expected 401 when user id header is missing");
    }

    @Test
    void returns400WhenActionHeaderIsRequiredButMissing() throws Exception {
        httpAuthzProperties.setActionRequired(true);

        final MockHttpServletRequest req = new MockHttpServletRequest(METHOD_GET, PATH_HELLO);
        req.addHeader(USER_ID_HEADER, USER_ID);
        final MockHttpServletResponse res = new MockHttpServletResponse();

        httpAuthzFilter.doFilter(req, res, filterChain);

        assertEquals(400, res.getStatus(), "Expected 400 when action header is required but missing");
    }

    @Test
    void allowsRequestWhenEngineApproves() throws Exception {
        final MockHttpServletRequest req = new MockHttpServletRequest(METHOD_GET, PATH_HELLO);
        req.addHeader(USER_ID_HEADER, USER_ID);
        final MockHttpServletResponse res = new MockHttpServletResponse();

        final IdentityResponse identityResponse = mockIdentity(USER_ID);
        when(identityClient.fetchIdentity(USER_ID)).thenReturn(identityResponse);
        when(identityToGroupsMapper.toGroups(identityResponse)).thenReturn(Set.of(GROUP_LEGAL_ADVISERS));
        when(droolsAuthzEngine.evaluate(any(), any())).thenReturn(true);

        httpAuthzFilter.doFilter(req, res, filterChain);

        assertEquals(200, res.getStatus(), "Expected 200 when engine approves");
    }

    @Test
    void principalAttributeIsSetWhenEngineApproves() throws Exception {
        final MockHttpServletRequest req = new MockHttpServletRequest(METHOD_GET, PATH_HELLO);
        req.addHeader(USER_ID_HEADER, USER_ID);
        final MockHttpServletResponse res = new MockHttpServletResponse();

        final IdentityResponse identityResponse = mockIdentity(USER_ID);
        when(identityClient.fetchIdentity(USER_ID)).thenReturn(identityResponse);
        when(identityToGroupsMapper.toGroups(identityResponse)).thenReturn(Set.of(GROUP_LEGAL_ADVISERS));
        when(droolsAuthzEngine.evaluate(any(), any())).thenReturn(true);

        httpAuthzFilter.doFilter(req, res, filterChain);

        final Object principalAttr = req.getAttribute(AuthzPrincipal.class.getName());
        assertNotNull(principalAttr, "Principal should be attached to the request");
    }

    @Test
    void deniesRequestWhenEngineRejects() throws Exception {
        final MockHttpServletRequest req = new MockHttpServletRequest(METHOD_GET, PATH_HELLO);
        req.addHeader(USER_ID_HEADER, USER_ID);
        final MockHttpServletResponse res = new MockHttpServletResponse();

        final IdentityResponse identityResponse = mockIdentity(USER_ID);
        when(identityClient.fetchIdentity(USER_ID)).thenReturn(identityResponse);
        when(identityToGroupsMapper.toGroups(identityResponse)).thenReturn(Set.of("Guests"));
        when(droolsAuthzEngine.evaluate(any(), any())).thenReturn(false);

        httpAuthzFilter.doFilter(req, res, filterChain);

        assertEquals(403, res.getStatus(), "Expected 403 when engine rejects");
    }

    @Test
    void usesHeaderActionName() throws IOException, ServletException {
        final MockHttpServletRequest req = new MockHttpServletRequest(METHOD_GET, PATH_HELLO);
        req.addHeader(USER_ID_HEADER, USER_ID);
        req.addHeader(ACTION_HEADER, ACTION_GET_HELLO);
        final MockHttpServletResponse res = new MockHttpServletResponse();

        final IdentityResponse identityResponse = mockIdentity(USER_ID);
        when(identityClient.fetchIdentity(USER_ID)).thenReturn(identityResponse);
        when(identityToGroupsMapper.toGroups(identityResponse)).thenReturn(Set.of(GROUP_LEGAL_ADVISERS));
        final ArgumentCaptor<Action> captor = ArgumentCaptor.forClass(Action.class);
        when(droolsAuthzEngine.evaluate(any(), captor.capture())).thenReturn(true);

        httpAuthzFilter.doFilter(req, res, filterChain);

        assertEquals(ACTION_GET_HELLO, captor.getValue().name(), "Action name should match header");
    }

    @Test
    void usesHeaderMethodAttribute() throws IOException, ServletException {
        final MockHttpServletRequest req = new MockHttpServletRequest(METHOD_GET, PATH_HELLO);
        req.addHeader(USER_ID_HEADER, USER_ID);
        req.addHeader(ACTION_HEADER, ACTION_GET_HELLO);
        final MockHttpServletResponse res = new MockHttpServletResponse();

        final IdentityResponse identityResponse = mockIdentity(USER_ID);
        when(identityClient.fetchIdentity(USER_ID)).thenReturn(identityResponse);
        when(identityToGroupsMapper.toGroups(identityResponse)).thenReturn(Set.of(GROUP_LEGAL_ADVISERS));
        final ArgumentCaptor<Action> captor = ArgumentCaptor.forClass(Action.class);
        when(droolsAuthzEngine.evaluate(any(), captor.capture())).thenReturn(true);

        httpAuthzFilter.doFilter(req, res, filterChain);

        assertEquals(METHOD_GET, captor.getValue().attributes().get("method"), "Method attribute should be GET");
    }

    @Test
    void usesHeaderPathAttribute() throws IOException, ServletException {
        final MockHttpServletRequest req = new MockHttpServletRequest(METHOD_GET, PATH_HELLO);
        req.addHeader(USER_ID_HEADER, USER_ID);
        req.addHeader(ACTION_HEADER, ACTION_GET_HELLO);
        final MockHttpServletResponse res = new MockHttpServletResponse();

        final IdentityResponse identityResponse = mockIdentity(USER_ID);
        when(identityClient.fetchIdentity(USER_ID)).thenReturn(identityResponse);
        when(identityToGroupsMapper.toGroups(identityResponse)).thenReturn(Set.of(GROUP_LEGAL_ADVISERS));
        final ArgumentCaptor<Action> captor = ArgumentCaptor.forClass(Action.class);
        when(droolsAuthzEngine.evaluate(any(), captor.capture())).thenReturn(true);

        httpAuthzFilter.doFilter(req, res, filterChain);

        assertEquals(PATH_HELLO, captor.getValue().attributes().get("path"), "Path attribute should be /api/hello");
    }

    @Test
    void computesActionName() throws IOException, ServletException {
        httpAuthzProperties.setActionRequired(false);

        final MockHttpServletRequest req = new MockHttpServletRequest(METHOD_POST, PATH_ECHO);
        req.addHeader(USER_ID_HEADER, USER_ID);
        final MockHttpServletResponse res = new MockHttpServletResponse();

        final IdentityResponse identityResponse = mockIdentity(USER_ID);
        when(identityClient.fetchIdentity(USER_ID)).thenReturn(identityResponse);
        when(identityToGroupsMapper.toGroups(identityResponse)).thenReturn(Set.of(GROUP_LEGAL_ADVISERS));
        final ArgumentCaptor<Action> captor = ArgumentCaptor.forClass(Action.class);
        when(droolsAuthzEngine.evaluate(any(), captor.capture())).thenReturn(true);

        httpAuthzFilter.doFilter(req, res, filterChain);

        assertEquals(ACTION_POST_ECHO, captor.getValue().name(), "Computed action should be method + path");
    }

    @Test
    void computesMethodAttribute() throws IOException, ServletException {
        httpAuthzProperties.setActionRequired(false);

        final MockHttpServletRequest req = new MockHttpServletRequest(METHOD_POST, PATH_ECHO);
        req.addHeader(USER_ID_HEADER, USER_ID);
        final MockHttpServletResponse res = new MockHttpServletResponse();

        final IdentityResponse identityResponse = mockIdentity(USER_ID);
        when(identityClient.fetchIdentity(USER_ID)).thenReturn(identityResponse);
        when(identityToGroupsMapper.toGroups(identityResponse)).thenReturn(Set.of(GROUP_LEGAL_ADVISERS));
        final ArgumentCaptor<Action> captor = ArgumentCaptor.forClass(Action.class);
        when(droolsAuthzEngine.evaluate(any(), captor.capture())).thenReturn(true);

        httpAuthzFilter.doFilter(req, res, filterChain);

        assertEquals(METHOD_POST, captor.getValue().attributes().get("method"), "Method attribute should be POST");
    }

    @Test
    void computesPathAttribute() throws IOException, ServletException {
        httpAuthzProperties.setActionRequired(false);

        final MockHttpServletRequest req = new MockHttpServletRequest(METHOD_POST, PATH_ECHO);
        req.addHeader(USER_ID_HEADER, USER_ID);
        final MockHttpServletResponse res = new MockHttpServletResponse();

        final IdentityResponse identityResponse = mockIdentity(USER_ID);
        when(identityClient.fetchIdentity(USER_ID)).thenReturn(identityResponse);
        when(identityToGroupsMapper.toGroups(identityResponse)).thenReturn(Set.of(GROUP_LEGAL_ADVISERS));
        final ArgumentCaptor<Action> captor = ArgumentCaptor.forClass(Action.class);
        when(droolsAuthzEngine.evaluate(any(), captor.capture())).thenReturn(true);

        httpAuthzFilter.doFilter(req, res, filterChain);

        assertEquals(PATH_ECHO, captor.getValue().attributes().get("path"), "Path attribute should be /api/echo");
    }

    @Test
    void honorsMultipleExcludePrefixes() throws Exception {
        httpAuthzProperties.setExcludePathPrefixes(List.of("/health/", "/metrics/", "/usersgroups-query-api/"));

        final MockHttpServletRequest req = new MockHttpServletRequest(METHOD_GET, PATH_EXCLUDED_METRICS);
        final MockHttpServletResponse res = new MockHttpServletResponse();

        httpAuthzFilter.doFilter(req, res, filterChain);

        verify(filterChain, times(1)).doFilter(req, res);
    }

    @Test
    void resolvesActionFromContentTypeVendorWinsOverHeader() throws Exception {
        final MockHttpServletRequest req = new MockHttpServletRequest(METHOD_POST, "/sjp/anything");
        req.addHeader(USER_ID_HEADER, USER_ID);
        req.addHeader("Content-Type", "application/vnd.sjp.delete-financial-means+json");
        req.addHeader(ACTION_HEADER, "POST /sjp/anything"); // should be ignored in favor of vendor
        final MockHttpServletResponse res = new MockHttpServletResponse();

        final IdentityResponse identityResponse = mockIdentity(USER_ID);
        when(identityClient.fetchIdentity(USER_ID)).thenReturn(identityResponse);
        when(identityToGroupsMapper.toGroups(identityResponse)).thenReturn(Set.of(GROUP_LEGAL_ADVISERS));

        final ArgumentCaptor<Action> captor = ArgumentCaptor.forClass(Action.class);
        when(droolsAuthzEngine.evaluate(any(), captor.capture())).thenReturn(true);

        httpAuthzFilter.doFilter(req, res, filterChain);

        assertEquals("sjp.delete-financial-means", captor.getValue().name(),
                "Vendor token from Content-Type must take priority");
    }

    @Test
    void resolvesActionFromAcceptWhenNoContentType() throws Exception {
        final MockHttpServletRequest req = new MockHttpServletRequest(METHOD_GET, "/hearing/draft-result");
        req.addHeader(USER_ID_HEADER, USER_ID);
        req.addHeader("Accept", "application/json, application/vnd.hearing.get-draft-result+json;q=0.9");
        final MockHttpServletResponse res = new MockHttpServletResponse();

        final IdentityResponse identityResponse = mockIdentity(USER_ID);
        when(identityClient.fetchIdentity(USER_ID)).thenReturn(identityResponse);
        when(identityToGroupsMapper.toGroups(identityResponse)).thenReturn(Set.of(GROUP_LEGAL_ADVISERS));

        final ArgumentCaptor<Action> captor = ArgumentCaptor.forClass(Action.class);
        when(droolsAuthzEngine.evaluate(any(), captor.capture())).thenReturn(true);

        httpAuthzFilter.doFilter(req, res, filterChain);

        assertEquals("hearing.get-draft-result", captor.getValue().name(),
                "Vendor token from Accept must be used when Content-Type is absent");
    }

    @Test
    void validate_userid_should_reject_none_guid() {
        assertThat(httpAuthzFilter.validateUserId(null)).isEmpty();
        assertThat(httpAuthzFilter.validateUserId("")).isEmpty();
        assertThat(httpAuthzFilter.validateUserId("bad")).isEmpty();
        assertThat(httpAuthzFilter.validateUserId("a05078bd")).isEmpty();
        assertThat(httpAuthzFilter.validateUserId("a05078bd-b189-4fd9-8c6e")).isEmpty();
        assertThat(httpAuthzFilter.validateUserId("a05078bd-b189-4fd9-8c6e-181e9a1234567")).isEmpty();
        assertThat(httpAuthzFilter.validateUserId(USER_ID + "0")).isEmpty();
    }

    @Test
    void validate_userid_should_return_good_guid() {
        assertThat(httpAuthzFilter.validateUserId("a05078bd-b189-4fd9-8c6e-181e9a123456").get()).isEqualTo(USER_ID);
        assertThat(httpAuthzFilter.validateUserId("E3F58BF7-FB59-4E5C-8ED9-E6A0F5966743").get()).isEqualTo(USER_ID_UC);
    }

    private static IdentityResponse mockIdentity(final UUID userId) {
        final IdentityResponse identity = mock(IdentityResponse.class);
        when(identity.userId()).thenReturn(userId);
        return identity;
    }
}
