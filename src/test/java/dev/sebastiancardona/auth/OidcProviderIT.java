package dev.sebastiancardona.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
 * The protocol works end to end: discovery, JWKS, authorization code + PKCE,
 * claims, userinfo, refresh rotation. If SAS internals drift on upgrade, these
 * fail loudly.
 */
class OidcProviderIT extends IntegrationTest {

    private static final String REDIRECT = "https://demo.example/callback";

    @Autowired MockMvc mockMvc;
    @Autowired ClientService clientService;
    @Autowired ObjectMapper mapper;

    private String clientId;
    private String clientSecret;

    @BeforeEach
    void registerClient() {
        clientId = "it-" + UUID.randomUUID().toString().substring(0, 8);
        var created = clientService.create(null, clientId, "IT client", true,
                List.of(REDIRECT), null, null);
        clientSecret = created.clientSecret();
    }

    @Test
    void discoveryDocumentAdvertisesCodePlusPkceOnly() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authorization_endpoint").exists())
                .andExpect(jsonPath("$.token_endpoint").exists())
                .andExpect(jsonPath("$.jwks_uri").exists())
                .andExpect(jsonPath("$.code_challenge_methods_supported",
                        org.hamcrest.Matchers.hasItem("S256")))
                .andExpect(jsonPath("$.grant_types_supported",
                        org.hamcrest.Matchers.not(org.hamcrest.Matchers.hasItem("password"))))
                .andExpect(jsonPath("$.response_types_supported",
                        org.hamcrest.Matchers.not(org.hamcrest.Matchers.hasItem("token"))));
    }

    @Test
    void jwksPublishesAtLeastOneRsaKey() throws Exception {
        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].kid").exists());
    }

    @Test
    void fullCodePlusPkceFlowIssuesTokensWithClaimsAndRotatesRefresh() throws Exception {
        String verifier = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("a-code-verifier-that-is-long-enough-for-rfc-7636".getBytes());
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));

        // 1. human logs in
        MvcResult login = mockMvc.perform(formLogin("/login").user(ADMIN_EMAIL).password(ADMIN_PASSWORD))
                .andExpect(authenticated())
                .andReturn();
        MockHttpSession session = (MockHttpSession) login.getRequest().getSession(false);

        // 2. authorize with PKCE → code on the redirect uri
        MvcResult authorize = mockMvc.perform(get("/oauth2/authorize")
                        .session(session)
                        .queryParam("response_type", "code")
                        .queryParam("client_id", clientId)
                        .queryParam("redirect_uri", REDIRECT)
                        .queryParam("scope", "openid profile")
                        .queryParam("state", "xyz")
                        .queryParam("code_challenge", challenge)
                        .queryParam("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        String location = authorize.getResponse().getRedirectedUrl();
        assertThat(location).startsWith(REDIRECT).contains("code=");
        String code = location.replaceAll(".*[?&]code=([^&]+).*", "$1");

        // 3. exchange code + verifier for tokens
        JsonNode tokens = tokenCall(
                "grant_type", "authorization_code",
                "code", code,
                "redirect_uri", REDIRECT,
                "code_verifier", verifier);
        assertThat(tokens.has("access_token")).isTrue();
        assertThat(tokens.has("refresh_token")).isTrue();
        assertThat(tokens.has("id_token")).isTrue();

        // 4. claims: groups + kid present, and the kid is published in the JWKS
        JsonNode payload = decodeJwtPayload(tokens.get("access_token").asText());
        assertThat(payload.get("groups")).isNotNull();
        assertThat(payload.get("groups").toString()).contains("admin");
        JsonNode header = decodeJwtHeader(tokens.get("access_token").asText());
        String kid = header.get("kid").asText();
        MvcResult jwks = mockMvc.perform(get("/oauth2/jwks")).andReturn();
        assertThat(jwks.getResponse().getContentAsString()).contains(kid);

        // 5. userinfo accepts the access token
        MvcResult userinfo = mockMvc.perform(get("/userinfo")
                        .header("Authorization", "Bearer " + tokens.get("access_token").asText()))
                .andReturn();
        assertThat(userinfo.getResponse().getStatus())
                .withFailMessage("userinfo returned %s, WWW-Authenticate: %s, body: %s",
                        userinfo.getResponse().getStatus(),
                        userinfo.getResponse().getHeader("WWW-Authenticate"),
                        userinfo.getResponse().getContentAsString())
                .isEqualTo(200);
        assertThat(mapper.readTree(userinfo.getResponse().getContentAsString())
                .get("sub").asText()).isEqualTo(ADMIN_EMAIL);

        // 6. refresh rotates: new token pair, old refresh token dies
        String refresh1 = tokens.get("refresh_token").asText();
        JsonNode refreshed = tokenCall("grant_type", "refresh_token", "refresh_token", refresh1);
        assertThat(refreshed.get("refresh_token").asText()).isNotEqualTo(refresh1);

        mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", basic())
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refresh1))
                .andExpect(status().isBadRequest());
    }

    @Test
    void authorizeWithoutPkceIsRejected() throws Exception {
        MvcResult login = mockMvc.perform(formLogin("/login").user(ADMIN_EMAIL).password(ADMIN_PASSWORD))
                .andReturn();
        MockHttpSession session = (MockHttpSession) login.getRequest().getSession(false);

        MvcResult result = mockMvc.perform(get("/oauth2/authorize")
                        .session(session)
                        .queryParam("response_type", "code")
                        .queryParam("client_id", clientId)
                        .queryParam("redirect_uri", REDIRECT)
                        .queryParam("scope", "openid")
                        .queryParam("state", "xyz"))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        // requireProofKey(true): no code_challenge → error, never a code
        assertThat(result.getResponse().getRedirectedUrl()).doesNotContain("code=");
    }

    private JsonNode tokenCall(String... params) throws Exception {
        var request = post("/oauth2/token").header("Authorization", basic());
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

    private String basic() {
        return "Basic " + Base64.getEncoder()
                .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
    }

    private JsonNode decodeJwtPayload(String jwt) throws Exception {
        return mapper.readTree(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]));
    }

    private JsonNode decodeJwtHeader(String jwt) throws Exception {
        return mapper.readTree(Base64.getUrlDecoder().decode(jwt.split("\\.")[0]));
    }
}
