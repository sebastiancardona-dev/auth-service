package dev.sebastiancardona.auth.config;

import dev.sebastiancardona.auth.domain.User;
import dev.sebastiancardona.auth.keys.KeyRotationService;
import dev.sebastiancardona.auth.repo.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * First-run state: at least one signing key must exist before any token is
 * minted, and the admin account is seeded once when the users table is empty
 * (same pattern as MoneyTrckr's bootstrap).
 */
@Component
public class BootstrapSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(BootstrapSeeder.class);

    private final KeyRotationService keys;
    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final AuthProperties props;

    public BootstrapSeeder(KeyRotationService keys, UserRepository users,
                           PasswordEncoder passwordEncoder, AuthProperties props) {
        this.keys = keys;
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.props = props;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        keys.ensureUsableKey();

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
}
