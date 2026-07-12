package dev.sebastiancardona.auth.audit;

import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Append-only audit trail. Raw JDBC on purpose: no entity, no update path,
 * nothing to accidentally mutate.
 */
@Service
public class AuditService {

    public static final String LOGIN_OK = "LOGIN_OK";
    public static final String LOGIN_FAIL = "LOGIN_FAIL";
    public static final String LOGIN_RATE_LIMITED = "LOGIN_RATE_LIMITED";
    public static final String INVITE_MINTED = "INVITE_MINTED";
    public static final String INVITE_REDEEMED = "INVITE_REDEEMED";
    public static final String INVITE_REVOKED = "INVITE_REVOKED";
    public static final String USER_REGISTERED = "USER_REGISTERED";
    public static final String USER_DISABLED = "USER_DISABLED";
    public static final String USER_GROUPS_CHANGED = "USER_GROUPS_CHANGED";
    public static final String CLIENT_REGISTERED = "CLIENT_REGISTERED";
    public static final String CLIENT_DELETED = "CLIENT_DELETED";
    public static final String KEY_ROTATED = "KEY_ROTATED";

    private final JdbcTemplate jdbc;
    private final com.fasterxml.jackson.databind.ObjectMapper mapper;

    public AuditService(JdbcTemplate jdbc, com.fasterxml.jackson.databind.ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    public void record(String event, UUID actorId, String subject, Map<String, Object> detail, String ip) {
        String json = null;
        if (detail != null) {
            try {
                json = mapper.writeValueAsString(detail);
            } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
                json = "{\"_serialization_error\":true}";
            }
        }
        jdbc.update(
                "insert into audit_events (event, actor_id, subject, detail, ip) values (?, ?, ?, ?::jsonb, ?)",
                event, actorId, subject, json, ip);
    }
}
