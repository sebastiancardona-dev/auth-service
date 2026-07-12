package dev.sebastiancardona.auth.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "invites")
public class Invite {

    @Id
    @GeneratedValue
    private UUID id;

    @Column(name = "token_hash", nullable = false, unique = true)
    private String tokenHash;

    @Column(name = "created_by", nullable = false)
    private UUID createdBy;

    @Column(name = "group_id", nullable = false)
    private String groupId;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "max_uses", nullable = false)
    private int maxUses;

    @Column(nullable = false)
    private int uses;

    private String note;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "created_at", nullable = false, updatable = false, insertable = false)
    private Instant createdAt;

    protected Invite() {}

    public Invite(String tokenHash, UUID createdBy, String groupId, Instant expiresAt, int maxUses, String note) {
        this.tokenHash = tokenHash;
        this.createdBy = createdBy;
        this.groupId = groupId;
        this.expiresAt = expiresAt;
        this.maxUses = maxUses;
        this.note = note;
    }

    public UUID getId() { return id; }
    public String getTokenHash() { return tokenHash; }
    public UUID getCreatedBy() { return createdBy; }
    public String getGroupId() { return groupId; }
    public Instant getExpiresAt() { return expiresAt; }
    public int getMaxUses() { return maxUses; }
    public int getUses() { return uses; }
    public String getNote() { return note; }
    public Instant getRevokedAt() { return revokedAt; }
    public Instant getCreatedAt() { return createdAt; }

    public boolean isRedeemable(Instant now) {
        return revokedAt == null && expiresAt.isAfter(now) && uses < maxUses;
    }

    public void redeem() { this.uses++; }
    public void revoke() { this.revokedAt = Instant.now(); }
}
