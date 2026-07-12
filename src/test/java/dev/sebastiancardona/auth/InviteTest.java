package dev.sebastiancardona.auth;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sebastiancardona.auth.domain.Invite;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** Pure-JVM redeemability rules (runs in the default surefire pass). */
class InviteTest {

    private final Instant now = Instant.parse("2026-07-12T12:00:00Z");

    private Invite invite(Instant expiresAt, int maxUses) {
        return new Invite("hash", UUID.randomUUID(), "friend", expiresAt, maxUses, null);
    }

    @Test
    void liveInviteIsRedeemable() {
        assertThat(invite(now.plus(1, ChronoUnit.DAYS), 1).isRedeemable(now)).isTrue();
    }

    @Test
    void expiredInviteIsNot() {
        assertThat(invite(now.minus(1, ChronoUnit.SECONDS), 1).isRedeemable(now)).isFalse();
    }

    @Test
    void exhaustedInviteIsNot() {
        Invite invite = invite(now.plus(1, ChronoUnit.DAYS), 2);
        invite.redeem();
        invite.redeem();
        assertThat(invite.isRedeemable(now)).isFalse();
    }

    @Test
    void revokedInviteIsNot() {
        Invite invite = invite(now.plus(1, ChronoUnit.DAYS), 1);
        invite.revoke();
        assertThat(invite.isRedeemable(now)).isFalse();
    }
}
