package dev.sebastiancardona.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.sebastiancardona.auth.invite.InviteService;
import dev.sebastiancardona.auth.repo.UserRepository;
import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;

class InviteFlowIT extends IntegrationTest {

    @Autowired MockMvc mockMvc;
    @Autowired InviteService inviteService;
    @Autowired UserRepository users;

    @Test
    void registrationRequiresALiveInvite() throws Exception {
        // no token → no form
        mockMvc.perform(get("/register"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("no es válida")));

        // bogus token → no form
        mockMvc.perform(get("/register").queryParam("invite", "not-a-real-token"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("no es válida")));

        // POST with bogus token → error page, no user created
        long before = users.count();
        mockMvc.perform(post("/register").with(csrf())
                        .param("invite", "not-a-real-token")
                        .param("email", "eve@test.dev")
                        .param("password", "long-enough-password")
                        .param("displayName", "Eve"))
                .andExpect(status().isOk());
        assertThat(users.count()).isEqualTo(before);
    }

    @Test
    void inviteRedeemsIntoItsGroupAndExhausts() throws Exception {
        var minted = inviteService.mint(adminId(), "friend", Duration.ofDays(7), 1, "IT wave");
        String token = minted.plaintextToken();

        mockMvc.perform(get("/register").queryParam("invite", token))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Crear cuenta")));

        String email = "friend-" + UUID.randomUUID().toString().substring(0, 8) + "@test.dev";
        mockMvc.perform(post("/register").with(csrf())
                        .param("invite", token)
                        .param("email", email)
                        .param("password", "long-enough-password")
                        .param("displayName", "Test Friend"))
                .andExpect(redirectedUrl("/login?registered"));

        var user = users.findByEmail(email).orElseThrow();
        assertThat(user.getGroups()).containsExactly("friend");

        // max_uses=1 → the same link is dead now
        mockMvc.perform(get("/register").queryParam("invite", token))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("no es válida")));
    }

    @Test
    void revokedInviteStopsRedeeming() {
        var minted = inviteService.mint(adminId(), "recruiter", Duration.ofDays(7), 10, null);
        inviteService.revoke(minted.invite().getId(), adminId());

        assertThat(inviteService.peek(minted.plaintextToken())).isEmpty();
        assertThatThrownBy(() -> inviteService.redeem(
                minted.plaintextToken(), "x@test.dev", "long-enough-password", "X", null))
                .isInstanceOf(InviteService.InvalidInviteException.class);
    }

    @Test
    void duplicateEmailIsRejectedWithoutBurningTheInvite() {
        var minted = inviteService.mint(adminId(), "friend", Duration.ofDays(7), 5, null);
        assertThatThrownBy(() -> inviteService.redeem(
                minted.plaintextToken(), ADMIN_EMAIL, "long-enough-password", "Dup", null))
                .isInstanceOf(InviteService.InvalidInviteException.class);
        // uses unchanged: the transaction rolled back nothing partial
        assertThat(inviteService.peek(minted.plaintextToken())).isPresent();
    }

    private UUID adminId() {
        return users.findByEmail(ADMIN_EMAIL).orElseThrow().getId();
    }
}
