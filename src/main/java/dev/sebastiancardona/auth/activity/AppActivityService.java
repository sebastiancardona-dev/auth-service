package dev.sebastiancardona.auth.activity;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Tracks which apps (OIDC clients) each user actually uses. Touched at
 * access-token issuance — the one point where user and client meet on every
 * grant, including refreshes. Raw JDBC like the audit trail: an upsert and
 * two reads, nothing worth an entity.
 */
@Service
public class AppActivityService {

    public record AppUsage(String clientId, Instant firstUsedAt, Instant lastUsedAt, long useCount) {}

    private final JdbcTemplate jdbc;

    public AppActivityService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public void touch(UUID userId, String clientId) {
        jdbc.update("""
                insert into user_app_activity (user_id, client_id) values (?, ?)
                on conflict (user_id, client_id)
                do update set last_used_at = now(), use_count = user_app_activity.use_count + 1
                """, userId, clientId);
    }

    public List<AppUsage> forUser(UUID userId) {
        return jdbc.query("""
                select client_id, first_used_at, last_used_at, use_count
                from user_app_activity where user_id = ? order by last_used_at desc
                """, this::usage, userId);
    }

    /** All users' activity in one query — the admin users list attaches these. */
    public Map<UUID, List<AppUsage>> byUser() {
        Map<UUID, List<AppUsage>> out = new HashMap<>();
        jdbc.query("""
                select user_id, client_id, first_used_at, last_used_at, use_count
                from user_app_activity order by last_used_at desc
                """, rs -> {
            out.computeIfAbsent(UUID.fromString(rs.getString("user_id")), k -> new java.util.ArrayList<>())
                    .add(usage(rs, 0));
        });
        return out;
    }

    private AppUsage usage(java.sql.ResultSet rs, int rowNum) throws java.sql.SQLException {
        return new AppUsage(rs.getString("client_id"),
                rs.getTimestamp("first_used_at").toInstant(),
                rs.getTimestamp("last_used_at").toInstant(),
                rs.getLong("use_count"));
    }
}
