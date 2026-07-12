package dev.sebastiancardona.auth.audit;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.stereotype.Component;

/** Every credential success/failure lands in the audit trail. */
@Component
public class AuthenticationAuditListener {

    private final AuditService audit;

    public AuthenticationAuditListener(AuditService audit) {
        this.audit = audit;
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        // token-endpoint grants fire this too; only log human logins
        if (event.getAuthentication() instanceof OAuth2AuthorizationGrantAuthenticationToken) return;
        audit.record(AuditService.LOGIN_OK, null, event.getAuthentication().getName(), null, null);
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        audit.record(AuditService.LOGIN_FAIL, null, event.getAuthentication().getName(),
                java.util.Map.of("reason", event.getException().getClass().getSimpleName()), null);
    }
}
