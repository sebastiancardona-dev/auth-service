package dev.sebastiancardona.auth.keys;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import dev.sebastiancardona.auth.config.AuthProperties;
import dev.sebastiancardona.auth.domain.SigningKey;
import dev.sebastiancardona.auth.repo.SigningKeyRepository;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * DB-backed JWKS with rotation. The newest non-retired key signs; every key still
 * inside its publication window stays in the JWKS so tokens it signed keep
 * verifying. Publication window = retire_after + the longest token lifetime
 * (refresh TTL), so nothing valid ever dangles.
 *
 * Key material generation and JOSE handling are delegated to the JDK and Nimbus —
 * this class decides *when* keys rotate, never *how* crypto works.
 */
@Service
public class KeyRotationService {

    private static final Logger log = LoggerFactory.getLogger(KeyRotationService.class);

    private final SigningKeyRepository repository;
    private final AuthProperties props;

    private volatile JWKSet cached = new JWKSet();
    private volatile String activeKid;

    public KeyRotationService(SigningKeyRepository repository, AuthProperties props) {
        this.repository = repository;
        this.props = props;
    }

    /**
     * SAS consumes this for both signing and the /oauth2/jwks document. The set holds
     * every still-published key; signing stays unambiguous because the token customizer
     * pins {@link #activeKid()} in the JWS header (NimbusJwtEncoder selects by kid and
     * refuses ambiguous matches).
     */
    public JWKSource<SecurityContext> jwkSource() {
        return (selector, context) -> selector.select(cached);
    }

    /** kid of the newest non-retired key — the only key that signs. */
    public String activeKid() {
        return activeKid;
    }

    @Transactional
    public void ensureUsableKey() {
        Instant now = Instant.now();
        boolean hasActive = repository.findAllByOrderByCreatedAtDesc().stream()
                .anyMatch(k -> k.getRetireAfter().isAfter(now));
        if (!hasActive) {
            generate(now);
        }
        reload();
    }

    /** Daily check — cheap no-op unless the newest key crossed its retire line. */
    @Scheduled(fixedRate = 6 * 60 * 60 * 1000, initialDelay = 60 * 60 * 1000)
    public void rotateIfDue() {
        ensureUsableKey();
    }

    private void generate(Instant now) {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair pair = gen.generateKeyPair();
            String kid = UUID.randomUUID().toString();
            Instant retireAfter = now.plus(Duration.ofDays(props.keys().rotationDays()));
            repository.save(new SigningKey(
                    kid,
                    Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                    Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()),
                    retireAfter));
            log.info("Generated signing key kid={} retireAfter={}", kid, retireAfter);
        } catch (Exception e) {
            throw new IllegalStateException("RSA key generation failed", e);
        }
    }

    private void reload() {
        Instant now = Instant.now();
        // keep publishing retired keys for one refresh-TTL past retirement
        Instant publishFloor = now.minus(props.token().refreshTtl());
        List<RSAKey> jwks = new ArrayList<>();
        String newestActive = null;
        for (SigningKey k : repository.findAllByOrderByCreatedAtDesc()) {
            if (k.getRetireAfter().isBefore(publishFloor)) continue;
            if (newestActive == null && k.getRetireAfter().isAfter(now)) {
                newestActive = k.getKid();
            }
            try {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                RSAPublicKey pub = (RSAPublicKey) kf.generatePublic(
                        new X509EncodedKeySpec(Base64.getDecoder().decode(k.getPublicKeyPem())));
                RSAPrivateKey priv = (RSAPrivateKey) kf.generatePrivate(
                        new PKCS8EncodedKeySpec(Base64.getDecoder().decode(k.getPrivateKeyPem())));
                jwks.add(new RSAKey.Builder(pub).privateKey(priv).keyID(k.getKid()).build());
            } catch (Exception e) {
                log.error("Skipping unloadable signing key kid={}", k.getKid(), e);
            }
        }
        this.cached = new JWKSet(List.copyOf(jwks));
        this.activeKid = newestActive;
        log.info("JWKS loaded: {} key(s) published, active kid={}", jwks.size(), newestActive);
    }
}
