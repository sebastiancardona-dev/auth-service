package dev.sebastiancardona.auth.config;

import dev.sebastiancardona.auth.admin.ClientService;
import dev.sebastiancardona.auth.domain.User;
import dev.sebastiancardona.auth.keys.KeyRotationService;
import dev.sebastiancardona.auth.repo.UserRepository;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * First-run state: at least one signing key must exist before any token is
 * minted, the admin account is seeded once when the users table is empty
 * (same pattern as MoneyTrckr's bootstrap), and the first-party admin-cli
 * client exists so an admin can ever obtain a token (chicken-and-egg breaker:
 * registering clients needs an admin token, which needs a client).
 */
@Component
public class BootstrapSeeder implements ApplicationRunner {

    /** Loopback redirect per RFC 8252 (native/CLI apps); ops/admin-token.py listens here. */
    public static final String ADMIN_CLI_CLIENT_ID = "admin-cli";
    public static final String ADMIN_CLI_REDIRECT = "http://127.0.0.1:8484/callback";

    private static final Logger log = LoggerFactory.getLogger(BootstrapSeeder.class);

    private final KeyRotationService keys;
    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final AuthProperties props;
    private final ClientService clients;
    private final RegisteredClientRepository registeredClients;

    public BootstrapSeeder(KeyRotationService keys, UserRepository users,
                           PasswordEncoder passwordEncoder, AuthProperties props,
                           ClientService clients, RegisteredClientRepository registeredClients) {
        this.keys = keys;
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.props = props;
        this.clients = clients;
        this.registeredClients = registeredClients;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        keys.ensureUsableKey();
        seedAdminUser();
        seedAdminCliClient();
    }

    private void seedAdminUser() {
        if (users.count() > 0) return;
        String email = props.bootstrap().adminEmail();
        String password = props.bootstrap().adminPassword();
        if (email == null || email.isBlank() || password == null || password.isBlank()) {
            log.warn("Users table is empty and no ADMIN_EMAIL/ADMIN_PASSWORD set — nobody can log in");
            return;
        }
        User admin = new User(email.toLowerCase().trim(),
                passwordEncoder.encode(password), props.bootstrap().adminName(), "es");
        admin.getGroups().add("admin");
        users.save(admin);
        log.info("Seeded admin account {}", email);
    }

    private void seedAdminCliClient() {
        if (registeredClients.findByClientId(ADMIN_CLI_CLIENT_ID) != null) return;
        clients.create(null, ADMIN_CLI_CLIENT_ID, "Admin CLI (ops/admin-token.py)",
                false, List.of(ADMIN_CLI_REDIRECT), null, null);
        log.info("Seeded first-party public client {}", ADMIN_CLI_CLIENT_ID);
    }
}
