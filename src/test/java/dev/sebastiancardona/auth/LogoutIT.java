package dev.sebastiancardona.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * The /connect/logout human-error path: a bare hit (stale bookmark, hand-typed
 * URL) lands on the friendly /signed-out page instead of SAS's naked 400, while
 * real RP-initiated logout still reaches the protocol filter untouched.
 */
class LogoutIT extends IntegrationTest {

    @Autowired MockMvc mockMvc;

    @Test
    void bareLogoutRedirectsToSignedOut() throws Exception {
        mockMvc.perform(get("/connect/logout"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/signed-out"));
    }

    @Test
    void logoutWithIdTokenHintStillReachesTheProtocolFilter() throws Exception {
        MvcResult result = mockMvc.perform(get("/connect/logout")
                        .queryParam("id_token_hint", "not-a-real-token"))
                .andReturn();
        // bogus hint → SAS rejects it; the point is our redirect didn't swallow it
        assertThat(result.getResponse().getRedirectedUrl()).isNotEqualTo("/signed-out");
        assertThat(result.getResponse().getStatus()).isEqualTo(400);
    }

    @Test
    void signedOutRendersAnonymouslyWithNothingToClose() throws Exception {
        mockMvc.perform(get("/signed-out"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("No hay ninguna sesión abierta")));
    }

    @Test
    void signedOutOffersLocalLogoutWhileTheSessionLives() throws Exception {
        MvcResult login = mockMvc.perform(formLogin("/login").user(ADMIN_EMAIL).password(ADMIN_PASSWORD))
                .andExpect(authenticated())
                .andReturn();
        MockHttpSession session = (MockHttpSession) login.getRequest().getSession(false);

        mockMvc.perform(get("/signed-out").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Tu sesión sigue abierta")))
                // the local-logout form, CSRF token included by Thymeleaf
                .andExpect(content().string(containsString("action=\"/logout\"")))
                .andExpect(content().string(containsString("_csrf")));
    }
}
