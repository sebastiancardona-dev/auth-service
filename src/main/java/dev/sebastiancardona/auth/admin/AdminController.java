package dev.sebastiancardona.auth.admin;

import dev.sebastiancardona.auth.audit.AuditService;
import dev.sebastiancardona.auth.config.AuthProperties;
import dev.sebastiancardona.auth.domain.Invite;
import dev.sebastiancardona.auth.domain.User;
import dev.sebastiancardona.auth.invite.InviteService;
import dev.sebastiancardona.auth.repo.InviteRepository;
import dev.sebastiancardona.auth.repo.UserRepository;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Headless admin surface (locked decision: the UI lives in Portal, project 06).
 * Requires a bearer token whose groups claim contains "admin" — enforced by the
 * /api/** security chain. Until Portal exists this is curl territory; see README.
 */
@RestController
@RequestMapping("/api/admin")
@Validated
public class AdminController {

    private final InviteService inviteService;
    private final ClientService clientService;
    private final InviteRepository invites;
    private final UserRepository users;
    private final JdbcTemplate jdbc;
    private final AuditService audit;
    private final AuthProperties props;

    public AdminController(InviteService inviteService, ClientService clientService,
                           InviteRepository invites, UserRepository users,
                           JdbcTemplate jdbc, AuditService audit, AuthProperties props) {
        this.inviteService = inviteService;
        this.clientService = clientService;
        this.invites = invites;
        this.users = users;
        this.jdbc = jdbc;
        this.audit = audit;
        this.props = props;
    }

    // ===== invites =====

    public record MintInviteRequest(
            @NotBlank @Pattern(regexp = "admin|recruiter|friend") String group,
            @Min(1) @Max(365) int ttlDays,
            @Min(1) @Max(100) int maxUses,
            String note) {}

    @PostMapping("/invites")
    public Map<String, Object> mintInvite(@RequestBody @Validated MintInviteRequest req,
                                          @AuthenticationPrincipal Jwt jwt) {
        var minted = inviteService.mint(actor(jwt), req.group(),
                Duration.ofDays(req.ttlDays()), req.maxUses(), req.note());
        return Map.of(
                "id", minted.invite().getId(),
                // shown exactly once; only the hash is stored
                "token", minted.plaintextToken(),
                "registerUrl", props.issuer() + "/register?invite=" + minted.plaintextToken(),
                "expiresAt", minted.invite().getExpiresAt(),
                "maxUses", minted.invite().getMaxUses());
    }

    public record InviteSummary(UUID id, String group, int uses, int maxUses, Instant expiresAt,
                                Instant revokedAt, String note, List<Redeemer> redemptions) {}

    public record Redeemer(String email, String displayName, Instant redeemedAt) {}

    @GetMapping("/invites")
    public List<InviteSummary> listInvites() {
        return invites.findAllByOrderByCreatedAtDesc().stream().map(this::summarize).toList();
    }

    private InviteSummary summarize(Invite invite) {
        List<Redeemer> redeemers = jdbc.query("""
                        select u.email, u.display_name, r.redeemed_at
                        from invite_redemptions r join users u on u.id = r.user_id
                        where r.invite_id = ? order by r.redeemed_at desc
                        """,
                (rs, i) -> new Redeemer(rs.getString("email"), rs.getString("display_name"),
                        rs.getTimestamp("redeemed_at").toInstant()),
                invite.getId());
        return new InviteSummary(invite.getId(), invite.getGroupId(), invite.getUses(),
                invite.getMaxUses(), invite.getExpiresAt(), invite.getRevokedAt(),
                invite.getNote(), redeemers);
    }

    @DeleteMapping("/invites/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void revokeInvite(@PathVariable UUID id, @AuthenticationPrincipal Jwt jwt) {
        inviteService.revoke(id, actor(jwt));
    }

    // ===== users =====

    public record UserSummary(UUID id, String email, String displayName,
                              Set<String> groups, boolean disabled, Instant createdAt) {}

    @GetMapping("/users")
    public List<UserSummary> listUsers() {
        return users.findAll().stream()
                .map(u -> new UserSummary(u.getId(), u.getEmail(), u.getDisplayName(),
                        u.getGroups(), u.isDisabled(), u.getCreatedAt()))
                .toList();
    }

    public record PatchUserRequest(@NotEmpty Set<@Pattern(regexp = "admin|recruiter|friend") String> groups,
                                   Boolean disabled) {}

    @PatchMapping("/users/{id}")
    @Transactional
    public UserSummary patchUser(@PathVariable UUID id, @RequestBody @Validated PatchUserRequest req,
                                 @AuthenticationPrincipal Jwt jwt) {
        User user = users.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        UUID actorId = actor(jwt);
        if (user.getId().equals(actorId) && (!req.groups().contains("admin")
                || Boolean.TRUE.equals(req.disabled()))) {
            // an admin locking themselves out is unrecoverable without DB surgery
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Refusing to demote/disable yourself");
        }
        user.getGroups().clear();
        user.getGroups().addAll(req.groups());
        if (req.disabled() != null) {
            if (req.disabled()) user.disable(); else user.enable();
            if (req.disabled()) {
                audit.record(AuditService.USER_DISABLED, actorId, user.getEmail(), null, null);
            }
        }
        audit.record(AuditService.USER_GROUPS_CHANGED, actorId, user.getEmail(),
                Map.of("groups", List.copyOf(req.groups())), null);
        return new UserSummary(user.getId(), user.getEmail(), user.getDisplayName(),
                user.getGroups(), user.isDisabled(), user.getCreatedAt());
    }

    // ===== clients =====

    public record CreateClientRequest(
            @NotBlank @Pattern(regexp = "[a-z0-9-]{2,50}") String clientId,
            @NotBlank String name,
            boolean confidential,
            @NotEmpty List<String> redirectUris,
            List<String> postLogoutRedirectUris,
            List<String> extraScopes) {}

    @PostMapping("/clients")
    public Map<String, Object> createClient(@RequestBody @Validated CreateClientRequest req,
                                            @AuthenticationPrincipal Jwt jwt) {
        var created = clientService.create(actor(jwt), req.clientId(), req.name(),
                req.confidential(), req.redirectUris(), req.postLogoutRedirectUris(), req.extraScopes());
        return created.clientSecret() == null
                ? Map.of("clientId", created.clientId())
                // secret shown exactly once; only the argon2 hash is stored
                : Map.of("clientId", created.clientId(), "clientSecret", created.clientSecret());
    }

    @GetMapping("/clients")
    public List<ClientService.ClientSummary> listClients() {
        return clientService.list();
    }

    @DeleteMapping("/clients/{clientId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteClient(@PathVariable String clientId, @AuthenticationPrincipal Jwt jwt) {
        clientService.delete(actor(jwt), clientId);
    }

    // ===== audit =====

    @GetMapping("/audit")
    public List<Map<String, Object>> audit(@RequestParam(defaultValue = "100") @Min(1) @Max(1000) int limit) {
        return jdbc.queryForList(
                "select at, event, actor_id, subject, detail, ip from audit_events order by at desc limit ?",
                limit);
    }

    private UUID actor(Jwt jwt) {
        String uid = jwt.getClaimAsString("uid");
        if (uid == null) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Token has no uid claim");
        }
        return UUID.fromString(uid);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, String> badRequest(IllegalArgumentException e) {
        return Map.of("error", e.getMessage());
    }
}
