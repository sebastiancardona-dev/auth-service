package dev.sebastiancardona.auth.invite;

import dev.sebastiancardona.auth.audit.AuditService;
import dev.sebastiancardona.auth.domain.Invite;
import dev.sebastiancardona.auth.domain.InviteRedemption;
import dev.sebastiancardona.auth.domain.User;
import dev.sebastiancardona.auth.repo.InviteRedemptionRepository;
import dev.sebastiancardona.auth.repo.InviteRepository;
import dev.sebastiancardona.auth.repo.UserRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Registration is impossible without a live invite. Tokens are 256-bit random,
 * shown once at mint time; only the SHA-256 lands in the database (a DB leak
 * must not leak usable invites). Multi-use by design: one link per audience,
 * everyone who redeems it joins the invite's group.
 */
@Service
public class InviteService {

    public record MintedInvite(Invite invite, String plaintextToken) {}

    private final InviteRepository invites;
    private final InviteRedemptionRepository redemptions;
    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final AuditService audit;
    private final SecureRandom random = new SecureRandom();

    public InviteService(InviteRepository invites, InviteRedemptionRepository redemptions,
                         UserRepository users, PasswordEncoder passwordEncoder, AuditService audit) {
        this.invites = invites;
        this.redemptions = redemptions;
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.audit = audit;
    }

    @Transactional
    public MintedInvite mint(UUID adminId, String groupId, Duration ttl, int maxUses, String note) {
        byte[] raw = new byte[32];
        random.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        Invite invite = invites.save(new Invite(
                sha256(token), adminId, groupId, Instant.now().plus(ttl), maxUses, note));
        audit.record(AuditService.INVITE_MINTED, adminId, invite.getId().toString(),
                Map.of("group", groupId, "maxUses", maxUses, "ttlDays", ttl.toDays()), null);
        return new MintedInvite(invite, token);
    }

    /** Peek without consuming — the register page shows the form only for live tokens. */
    @Transactional(readOnly = true)
    public Optional<Invite> peek(String token) {
        return invites.findByTokenHash(sha256(token))
                .filter(i -> i.isRedeemable(Instant.now()));
    }

    /** The whole redemption is one transaction: lock, validate, create, record. */
    @Transactional
    public User redeem(String token, String email, String password, String displayName, String ip) {
        Invite invite = invites.findByTokenHashForUpdate(sha256(token))
                .filter(i -> i.isRedeemable(Instant.now()))
                .orElseThrow(() -> new InvalidInviteException("Invite is not redeemable"));
        String normalized = email.toLowerCase().trim();
        if (users.existsByEmail(normalized)) {
            throw new InvalidInviteException("Email already registered");
        }
        User user = new User(normalized, passwordEncoder.encode(password), displayName.trim(), "es");
        user.getGroups().add(invite.getGroupId());
        user = users.save(user);
        invite.redeem();
        redemptions.save(new InviteRedemption(invite.getId(), user.getId()));
        audit.record(AuditService.INVITE_REDEEMED, user.getId(), invite.getId().toString(),
                Map.of("email", normalized, "group", invite.getGroupId()), ip);
        audit.record(AuditService.USER_REGISTERED, user.getId(), normalized,
                Map.of("group", invite.getGroupId()), ip);
        return user;
    }

    @Transactional
    public void revoke(UUID inviteId, UUID adminId) {
        Invite invite = invites.findById(inviteId)
                .orElseThrow(() -> new InvalidInviteException("No such invite"));
        invite.revoke();
        audit.record(AuditService.INVITE_REVOKED, adminId, inviteId.toString(), null, null);
    }

    private static String sha256(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static class InvalidInviteException extends RuntimeException {
        public InvalidInviteException(String message) {
            super(message);
        }
    }
}
