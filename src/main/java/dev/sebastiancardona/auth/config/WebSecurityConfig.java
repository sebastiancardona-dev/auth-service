package dev.sebastiancardona.auth.config;

import dev.sebastiancardona.auth.web.LoginRateLimitFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Two application chains behind the protocol chain (order 1, see
 * AuthorizationServerConfig):
 *
 *  - /api/** (order 2): stateless resource server. Only our own JWTs, no cookies,
 *    no CSRF surface. Admin endpoints demand the "admin" group claim.
 *  - everything else (order 3): the human surface — login form, registration,
 *    session cookies, CSRF on.
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Bean
    @Order(2)
    SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/admin/**").hasAuthority("GROUP_admin")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(rs -> rs.jwt(jwt ->
                        jwt.jwtAuthenticationConverter(groupsToAuthorities())));
        return http.build();
    }

    @Bean
    @Order(3)
    SecurityFilterChain webChain(HttpSecurity http, LoginRateLimitFilter rateLimit) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login", "/register", "/error",
                                "/health", "/health/**", "/info",
                                "/css/**", "/icons/**", "/favicon.ico", "/icon.svg").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .permitAll())
                .addFilterBefore(rateLimit, UsernamePasswordAuthenticationFilter.class)
                .logout(logout -> logout.logoutSuccessUrl("/login?logout"));
        return http.build();
    }

    /** groups claim → GROUP_<id> authorities, so hasAuthority("GROUP_admin") reads naturally. */
    private Converter<Jwt, AbstractAuthenticationToken> groupsToAuthorities() {
        return jwt -> {
            var groups = jwt.getClaimAsStringList("groups");
            var authorities = groups == null
                    ? java.util.List.<GrantedAuthority>of()
                    : groups.stream()
                            .<GrantedAuthority>map(g -> new SimpleGrantedAuthority("GROUP_" + g))
                            .toList();
            return new JwtAuthenticationToken(jwt, authorities, jwt.getSubject());
        };
    }
}
