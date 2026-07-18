package dev.sebastiancardona.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.sebastiancardona.auth.admin.ClientService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Per-app usage tracking (portal accounts dashboard, project 06): every
 * access-token mint — code grant and refresh alike — upserts (user, client),
 * and the admin users API exposes it.
 */
class AppActivityIT extends IntegrationTest {

    private static final String REDIRECT = "https://activity.example/callback";

    @Autowired MockMvc mockMvc;
    @Autowired ClientService clientService;
    @Autowired ObjectMapper mapper;

    private String clientId;
    private String clientSecret;

    @BeforeEach
    void registerClient() {
        clientId = "act-" + UUID.randomUUID().toString().substring(0, 8);
        var created = clientService.create(null, clientId, "Activity IT client", true,
                List.of(REDIRECT), null, null);
        clientSecret = created.clientSecret();
    }

    @Test
    void tokenMintsRecordActivityAndAdminUsersExposesIt() throws Exception {
        JsonNode tokens = fullCodeFlow();
        String accessToken = tokens.get("access_token").asText();

        // 1. the code grant recorded one use of this client
        JsonNode admin = findAdminUser(accessToken);
        JsonNode usage = usageFor(admin, clientId);
        assertThat(usage).isNotNull();
        assertThat(usage.get("useCount").asLong()).isEqualTo(1);
        assertThat(usage.get("firstUsedAt").asText()).isEqualTo(usage.get("lastUsedAt").asText());

        // 2. a refresh mints a new access token → same row, count bumped
        tokenCall("grant_type", "refresh_token",
                "refresh_token", tokens.get("refresh_token").asText());
        usage = usageFor(findAdminUser(accessToken), clientId);
        assertThat(usage.get("useCount").asLong()).isEqualTo(2);
    }

    private JsonNode findAdminUser(String bearer) throws Exception {
        MvcResult result = mockMvc.perform(get("/api/admin/users")
                        .header("Authorization", "Bearer " + bearer))
                .andReturn();
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        for (JsonNode user : mapper.readTree(result.getResponse().getContentAsString())) {
            if (ADMIN_EMAIL.equals(user.get("email").asText())) {
                return user;
            }
        }
        throw new AssertionError("admin user missing from /api/admin/users");
    }

    private JsonNode usageFor(JsonNode user, String clientId) {
        for (JsonNode app : user.get("apps")) {
            if (clientId.equals(app.get("clientId").asText())) {
                return app;
            }
        }
        return null;
    }

    private JsonNode fullCodeFlow() throws Exception {
        String verifier = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("an-activity-verifier-long-enough-for-rfc-7636".getBytes());
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));

        MvcResult login = mockMvc.perform(formLogin("/login").user(ADMIN_EMAIL).password(ADMIN_PASSWORD))
                .andReturn();
        MockHttpSession session = (MockHttpSession) login.getRequest().getSession(false);

        MvcResult authorize = mockMvc.perform(get("/oauth2/authorize")
                        .session(session)
                        .queryParam("response_type", "code")
                        .queryParam("client_id", clientId)
                        .queryParam("redirect_uri", REDIRECT)
                        .queryParam("scope", "openid profile")
                        .queryParam("state", "xyz")
                        .queryParam("code_challenge", challenge)
                        .queryParam("code_challenge_method", "S256"))
                .andReturn();
        String location = authorize.getResponse().getRedirectedUrl();
        assertThat(location).startsWith(REDIRECT).contains("code=");
        String code = location.replaceAll(".*[?&]code=([^&]+).*", "$1");

        return tokenCall(
                "grant_type", "authorization_code",
                "code", code,
                "redirect_uri", REDIRECT,
                "code_verifier", verifier);
    }

    private JsonNode tokenCall(String... params) throws Exception {
        var request = post("/oauth2/token").header("Authorization", "Basic " + Base64.getEncoder()
                .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8)));
        for (int i = 0; i < params.length; i += 2) {
            request = request.param(params[i], params[i + 1]);
        }
        MvcResult result = mockMvc.perform(request).andReturn();
        String body = result.getResponse().getContentAsString();
        assertThat(result.getResponse().getStatus())
                .withFailMessage("token endpoint returned %s: %s",
                        result.getResponse().getStatus(), body)
                .isEqualTo(200);
        return mapper.readTree(body);
    }
}
