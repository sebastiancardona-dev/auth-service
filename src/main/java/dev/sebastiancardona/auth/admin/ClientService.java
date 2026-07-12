package dev.sebastiancardona.auth.admin;

import dev.sebastiancardona.auth.audit.AuditService;
import dev.sebastiancardona.auth.config.AuthProperties;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * OIDC client registrations, with the ecosystem's policy baked in:
 * authorization code + PKCE for everyone (public AND confidential — RFC 9700
 * best practice), refresh rotation, no consent screen for first-party apps.
 */
@Service
public class ClientService {

    public record CreatedClient(String clientId, String clientSecret) {}

    public record ClientSummary(String clientId, String name, List<String> redirectUris,
                                List<String> scopes, boolean confidential) {}

    private final RegisteredClientRepository repository;
    private final JdbcTemplate jdbc;
    private final PasswordEncoder passwordEncoder;
    private final AuthProperties props;
    private final AuditService audit;
    private final SecureRandom random = new SecureRandom();

    public ClientService(RegisteredClientRepository repository, JdbcTemplate jdbc,
                         PasswordEncoder passwordEncoder, AuthProperties props, AuditService audit) {
        this.repository = repository;
        this.jdbc = jdbc;
        this.passwordEncoder = passwordEncoder;
        this.props = props;
        this.audit = audit;
    }

    @Transactional
    public CreatedClient create(UUID adminId, String clientId, String name, boolean confidential,
                                List<String> redirectUris, List<String> postLogoutRedirectUris,
                                List<String> extraScopes) {
        if (repository.findByClientId(clientId) != null) {
            throw new IllegalArgumentException("client_id already exists: " + clientId);
        }
        String secret = null;
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientName(name)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)                    // PKCE always, no exceptions
                        .requireAuthorizationConsent(false)       // first-party apps only
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(props.token().accessTtl())
                        .refreshTokenTimeToLive(props.token().refreshTtl())
                        .reuseRefreshTokens(props.token().reuseRefreshTokens())
                        .build());

        if (confidential) {
            byte[] raw = new byte[32];
            random.nextBytes(raw);
            secret = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientSecret(passwordEncoder.encode(secret));
        } else {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
        }
        redirectUris.forEach(builder::redirectUri);
        if (postLogoutRedirectUris != null) {
            postLogoutRedirectUris.forEach(builder::postLogoutRedirectUri);
        }
        if (extraScopes != null) {
            extraScopes.forEach(builder::scope);
        }
        repository.save(builder.build());
        audit.record(AuditService.CLIENT_REGISTERED, adminId, clientId,
                Map.of("confidential", confidential, "redirectUris", redirectUris), null);
        return new CreatedClient(clientId, secret);
    }

    public List<ClientSummary> list() {
        return jdbc.query("""
                        select client_id, client_name, redirect_uris, scopes, client_authentication_methods
                        from oauth2_registered_client order by client_id
                        """,
                (rs, i) -> new ClientSummary(
                        rs.getString("client_id"),
                        rs.getString("client_name"),
                        List.of(rs.getString("redirect_uris").split(",")),
                        List.of(rs.getString("scopes").split(",")),
                        !rs.getString("client_authentication_methods").contains("none")));
    }

    @Transactional
    public void delete(UUID adminId, String clientId) {
        int removed = jdbc.update("delete from oauth2_registered_client where client_id = ?", clientId);
        if (removed == 0) {
            throw new IllegalArgumentException("No such client: " + clientId);
        }
        audit.record(AuditService.CLIENT_DELETED, adminId, clientId, null, null);
    }
}
