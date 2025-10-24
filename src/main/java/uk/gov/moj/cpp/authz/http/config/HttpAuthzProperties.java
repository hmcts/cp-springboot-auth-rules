package uk.gov.moj.cpp.authz.http.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.Ordered;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@ConfigurationProperties(prefix = "authz.http")
@Setter
@Getter
public class HttpAuthzProperties {
    private boolean enabled;
    private String identityUrlRoot = "http://localhost:8080";
    private String identityUrlPath = "/usersgroups-query-api/query/api/rest/usersgroups/users/{userId}/permissions";
    private String userIdHeader = "CJSCPPUID";
    private String actionHeader = "CPP-ACTION";
    private String acceptHeader = "application/vnd.usersgroups.get-logged-in-user-permissions+json";
    private String droolsClasspathPattern = "classpath:/acl/**/*.drl";
    private boolean reloadOnEachRequest = true;
    private boolean actionRequired;
    private boolean denyWhenNoRules = true;
    private Map<String, String> groupAliases = new LinkedHashMap<>();
    private Integer filterOrder = Ordered.HIGHEST_PRECEDENCE + 30;
    private List<String> excludePathPrefixes = new ArrayList<>(List.of("/usersgroups-query-api/", "/actuator", "/error"));

    public void setExcludePathPrefixes(final List<String> excludePathPrefixes) {
        this.excludePathPrefixes = excludePathPrefixes == null ? java.util.Collections.emptyList() : excludePathPrefixes;
    }
}
