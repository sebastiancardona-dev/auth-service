package dev.sebastiancardona.auth.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import dev.sebastiancardona.auth.activity.AppActivityService;
import dev.sebastiancardona.auth.keys.KeyRotationService;
import dev.sebastiancardona.auth.user.EcosystemUserDetailsService;
import dev.sebastiancardona.auth.web.BareLogoutRedirectFilter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

/**
 * The protocol layer. Spring Authorization Server implements the RFCs
 * (6749 authorization framework, 7636 PKCE, OIDC Core); this class wires policy:
 * which flows exist (code + PKCE, refresh rotation — nothing else), where state
 * lives (JDBC), what the tokens claim (groups + per-app roles), and which key
 * signs (the rotation service's active kid).
 */
@Configuration
public class AuthorizationServerConfig {

    /** OAuth2/OIDC protocol endpoints — highest precedence, matched by path. */
    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();
        http
                .securityMatcher(authorizationServer.getEndpointsMatcher())
                .with(authorizationServer, server -> server.oidc(Customizer.withDefaults()))
                // bare GET /connect/logout (stale bookmark) → /signed-out, before the
                // OIDC logout endpoint filter gets a chance to 400 on the missing hint
                .addFilterBefore(new BareLogoutRedirectFilter(), SecurityContextHolderFilter.class)
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                // browsers get the login page; API callers get 401
                .exceptionHandling(ex -> ex.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                // userinfo endpoint accepts our own access tokens
                .oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings(AuthProperties props) {
        return AuthorizationServerSettings.builder().issuer(props.issuer()).build();
    }

    @Bean
    RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbc) {
        return new JdbcRegisteredClientRepository(jdbc);
    }

    @Bean
    OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbc, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationService(jdbc, clients);
    }

    @Bean
    OAuth2AuthorizationConsentService authorizationConsentService(
            JdbcTemplate jdbc, RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(jdbc, clients);
    }

    @Bean
    JWKSource<SecurityContext> jwkSource(KeyRotationService keys) {
        return keys.jwkSource();
    }

    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * Claims + signing-key policy for every JWT we mint (access and ID tokens):
     * - kid pinned to the active rotation key (see KeyRotationService)
     * - groups: ecosystem-wide ("admin", "recruiter", "friend")
     * - roles: per-app overrides, keyed by client_id
     * - name / locale for apps that render the user
     */
    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(
            KeyRotationService keys, EcosystemUserDetailsService users, JdbcTemplate jdbc,
            AppActivityService activity) {
        return context -> {
            context.getJwsHeader().keyId(keys.activeKid());

            String tokenType = context.getTokenType().getValue();
            if (!OAuth2TokenType.ACCESS_TOKEN.getValue().equals(tokenType)
                    && !OidcParameterNames.ID_TOKEN.equals(tokenType)) {
                return;
            }
            String email = context.getPrincipal().getName();
            users.findDomainUser(email).ifPresent(user -> {
                // access token is minted exactly once per grant (code or refresh),
                // so this is the "user X used app Y" heartbeat
                if (OAuth2TokenType.ACCESS_TOKEN.getValue().equals(tokenType)) {
                    activity.touch(user.getId(), context.getRegisteredClient().getClientId());
                }
                // plain ArrayList/HashMap only: JdbcOAuth2AuthorizationService round-trips
                // claims through Jackson with the Spring Security allowlist, which rejects
                // List.copyOf()'s ImmutableCollections types at userinfo time
                context.getClaims().claim("groups", new ArrayList<>(new TreeSet<>(user.getGroups())));
                context.getClaims().claim("name", user.getDisplayName());
                context.getClaims().claim("locale", user.getLocale());
                context.getClaims().claim("uid", user.getId().toString());

                String clientId = context.getRegisteredClient().getClientId();
                List<String> roles = jdbc.queryForList(
                        "select role from user_client_roles where user_id = ? and client_id = ? order by role",
                        String.class, user.getId(), clientId);
                if (!roles.isEmpty()) {
                    Map<String, Object> byApp = new HashMap<>();
                    byApp.put(clientId, new ArrayList<>(roles));
                    context.getClaims().claim("roles", byApp);
                }
            });
        };
    }

    /**
     * argon2id for new hashes; the delegating wrapper keeps old hashes verifiable
     * if parameters ever change (hash strings are self-describing).
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        Map<String, PasswordEncoder> encoders =
                Map.of("argon2", Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8());
        return new DelegatingPasswordEncoder("argon2", encoders);
    }
}
