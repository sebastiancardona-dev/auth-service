package dev.sebastiancardona.auth;

import org.junit.jupiter.api.Tag;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Singleton-container base (NOT @Container/@Testcontainers: the cached Spring
 * context outlives per-class containers — learned the hard way in MoneyTrckr).
 */
@SpringBootTest
@AutoConfigureMockMvc
@Tag("integration")
public abstract class IntegrationTest {

    static final String ADMIN_EMAIL = "admin@test.dev";
    static final String ADMIN_PASSWORD = "test-admin-password-123";

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    static {
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("auth.bootstrap.admin-email", () -> ADMIN_EMAIL);
        registry.add("auth.bootstrap.admin-password", () -> ADMIN_PASSWORD);
    }
}
