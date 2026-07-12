package dev.sebastiancardona.auth.web;

import dev.sebastiancardona.auth.audit.AuditService;
import dev.sebastiancardona.auth.config.AuthProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Sliding-window rate limit on credential attempts, keyed by username+IP.
 * In-memory on purpose: single instance, and a restart resetting counters is
 * an acceptable trade at this scale (documented in the case study).
 */
@Component
public class LoginRateLimitFilter extends OncePerRequestFilter {

    private record Window(Instant start, AtomicInteger count) {}

    private final Map<String, Window> windows = new ConcurrentHashMap<>();
    private final AuthProperties props;
    private final AuditService audit;

    public LoginRateLimitFilter(AuthProperties props, AuditService audit) {
        this.props = props;
        this.audit = audit;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !("POST".equals(request.getMethod()) && "/login".equals(request.getServletPath()));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String username = String.valueOf(request.getParameter("username")).toLowerCase().trim();
        String ip = clientIp(request);
        String key = username + "|" + ip;
        Instant now = Instant.now();

        Window w = windows.compute(key, (k, existing) -> {
            if (existing == null || existing.start().plus(props.login().window()).isBefore(now)) {
                return new Window(now, new AtomicInteger(1));
            }
            existing.count().incrementAndGet();
            return existing;
        });

        if (w.count().get() > props.login().maxAttempts()) {
            audit.record(AuditService.LOGIN_RATE_LIMITED, null, username, null, ip);
            response.sendRedirect("/login?error=rate");
            return;
        }
        // opportunistic cleanup so the map can't grow unbounded
        if (windows.size() > 10_000) {
            windows.entrySet().removeIf(e ->
                    e.getValue().start().plus(props.login().window()).isBefore(now));
        }
        chain.doFilter(request, response);
    }

    private String clientIp(HttpServletRequest request) {
        // Traefik terminates TLS and sets X-Forwarded-For; fall back to the socket
        String forwarded = request.getHeader("X-Forwarded-For");
        return forwarded != null ? forwarded.split(",")[0].trim() : request.getRemoteAddr();
    }
}
