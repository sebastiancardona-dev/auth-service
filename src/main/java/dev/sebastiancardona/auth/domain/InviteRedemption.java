package dev.sebastiancardona.auth.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "invite_redemptions")
public class InviteRedemption {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "invite_id", nullable = false)
    private UUID inviteId;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "redeemed_at", nullable = false, updatable = false, insertable = false)
    private Instant redeemedAt;

    protected InviteRedemption() {}

    public InviteRedemption(UUID inviteId, UUID userId) {
        this.inviteId = inviteId;
        this.userId = userId;
    }

    public Long getId() { return id; }
    public UUID getInviteId() { return inviteId; }
    public UUID getUserId() { return userId; }
    public Instant getRedeemedAt() { return redeemedAt; }
}
