package uk.gov.moj.cpp.authz.drools;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import uk.gov.moj.cpp.authz.http.AuthzPrincipal;
import uk.gov.moj.cpp.authz.http.config.HttpAuthzProperties;
import uk.gov.moj.cpp.authz.http.providers.UserAndGroupProvider;
import uk.gov.moj.cpp.authz.testsupport.TestConstants;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DroolsAuthzEngineTest {


    private static final String DROOLS_CLASSPATH_PATTERN = "classpath:/drool-test/**/*.drl";

    private final UUID userId = UUID.randomUUID();

    @BeforeAll
    static void prepare() {
        System.setProperty("mvel2.disable.jit", "true");
        System.setProperty("drools.compiler", "ECLIPSE");
        System.setProperty("drools.dialect.default", "java");
    }

    @Test
    @Timeout(5)
    void allowsWhenRuleMatchesActionAndGroup() {
        final HttpAuthzProperties properties = new HttpAuthzProperties();
        properties.setDroolsClasspathPattern(DROOLS_CLASSPATH_PATTERN);
        properties.setReloadOnEachRequest(false);
        properties.setDenyWhenNoRules(true);
        final DroolsAuthzEngine engine = new DroolsAuthzEngine(properties);

        final AuthzPrincipal principal =
                new AuthzPrincipal(userId, "fn", "ln", "u1@example.test", Set.of(TestConstants.GROUP_LA));
        final UserAndGroupProvider provider = (action, groups) -> {
            for (final String g : groups) {
                if (principal.groups().stream().anyMatch(s -> s.equalsIgnoreCase(g))) {
                    return true;
                }
            }
            return false;
        };
        final Action action = new Action(TestConstants.ACTION_HELLO, Map.of());
        assertTrue(engine.evaluate(provider, action), "Should have access");
    }

    @Test
    @Timeout(5)
    void deniesWhenNoRuleMatches() {
        final HttpAuthzProperties properties = new HttpAuthzProperties();
        properties.setDroolsClasspathPattern(DROOLS_CLASSPATH_PATTERN);
        properties.setReloadOnEachRequest(false);
        properties.setDenyWhenNoRules(true);
        final DroolsAuthzEngine engine = new DroolsAuthzEngine(properties);

        final UserAndGroupProvider provider = (action, groups) -> false;
        final Action action = new Action(TestConstants.ACTION_ECHO, Map.of());
        assertFalse(engine.evaluate(provider, action), "Access Denied");
    }

    @Test
    @Timeout(5)
    void allowsWhenVendorActionSjpDeleteFinancialMeansAndGroupIsLa() {
        final HttpAuthzProperties properties = new HttpAuthzProperties();
        properties.setDroolsClasspathPattern(DROOLS_CLASSPATH_PATTERN);
        properties.setReloadOnEachRequest(false);
        properties.setDenyWhenNoRules(true);
        final DroolsAuthzEngine engine = new DroolsAuthzEngine(properties);

        final AuthzPrincipal principal =
                new AuthzPrincipal(userId, "fn", "ln", "u2@example.test", Set.of(TestConstants.GROUP_LA));
        final UserAndGroupProvider provider = (action, groups) -> {
            for (final String g : groups) {
                if (principal.groups().stream().anyMatch(s -> s.equalsIgnoreCase(g))) {
                    return true;
                }
            }
            return false;
        };

        final Action action = new Action(TestConstants.ACTION_SJP_DELETE_FINANCIAL_MEANS, Map.of());
        assertTrue(engine.evaluate(provider, action), "Expected allow for sjp.delete-financial-means and LA group");
    }

    @Test
    @Timeout(5)
    void allowsWhenVendorActionHearingGetDraftResultAndGroupIsLa() {
        final HttpAuthzProperties properties = new HttpAuthzProperties();
        properties.setDroolsClasspathPattern(DROOLS_CLASSPATH_PATTERN);
        properties.setReloadOnEachRequest(false);
        properties.setDenyWhenNoRules(true);
        final DroolsAuthzEngine engine = new DroolsAuthzEngine(properties);

        final AuthzPrincipal principal =
                new AuthzPrincipal(userId, "fn", "ln", "u3@example.test", Set.of(TestConstants.GROUP_LA));
        final UserAndGroupProvider provider = (action, groups) -> {
            for (final String g : groups) {
                if (principal.groups().stream().anyMatch(s -> s.equalsIgnoreCase(g))) {
                    return true;
                }
            }
            return false;
        };

        final Action action = new Action(TestConstants.ACTION_HEARING_GET_DRAFT_RESULT, Map.of());
        assertTrue(engine.evaluate(provider, action), "Expected allow for hearing.get-draft-result and LA group");
    }
}
