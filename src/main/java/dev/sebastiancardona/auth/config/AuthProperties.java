package dev.sebastiancardona.auth.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth")
public record AuthProperties(
        String issuer,
        Token token,
        Keys keys,
        Login login,
        Bootstrap bootstrap) {

    public record Token(Duration accessTtl, Duration refreshTtl, boolean reuseRefreshTokens) {}

    public record Keys(int rotationDays) {}

    public record Login(int maxAttempts, Duration window) {}

    public record Bootstrap(String adminEmail, String adminPassword, String adminName) {}
}
