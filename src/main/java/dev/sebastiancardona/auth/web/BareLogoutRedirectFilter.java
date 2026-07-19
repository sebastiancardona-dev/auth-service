package dev.sebastiancardona.auth.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * OIDC RP-initiated logout requires id_token_hint, so a bare GET /connect/logout
 * (stale bookmark, hand-typed URL) earns a naked 400 from Spring Authorization
 * Server's OidcLogoutEndpointFilter. This sits at the front of the protocol chain
 * (see AuthorizationServerConfig) and diverts exactly that case to the friendly
 * /signed-out page; anything carrying RP-initiated parameters passes untouched.
 *
 * Not a @Component on purpose: Boot would also register it servlet-wide, and it
 * only belongs to the authorization-server chain.
 */
public class BareLogoutRedirectFilter extends OncePerRequestFilter {

    static final String LOGOUT_PATH = "/connect/logout";

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // requestURI, not servletPath: MockMvc leaves servletPath empty
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return !("GET".equals(request.getMethod())
                && LOGOUT_PATH.equals(path)
                && request.getParameter("id_token_hint") == null
                && request.getParameter("post_logout_redirect_uri") == null);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        response.sendRedirect("/signed-out");
    }
}
