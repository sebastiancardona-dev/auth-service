package dev.sebastiancardona.auth.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "signing_keys")
public class SigningKey {

    @Id
    @GeneratedValue
    private UUID id;

    @Column(nullable = false, unique = true)
    private String kid;

    @Column(name = "private_key_pem", nullable = false)
    private String privateKeyPem;

    @Column(name = "public_key_pem", nullable = false)
    private String publicKeyPem;

    @Column(name = "created_at", nullable = false, updatable = false, insertable = false)
    private Instant createdAt;

    @Column(name = "retire_after", nullable = false)
    private Instant retireAfter;

    protected SigningKey() {}

    public SigningKey(String kid, String privateKeyPem, String publicKeyPem, Instant retireAfter) {
        this.kid = kid;
        this.privateKeyPem = privateKeyPem;
        this.publicKeyPem = publicKeyPem;
        this.retireAfter = retireAfter;
    }

    public UUID getId() { return id; }
    public String getKid() { return kid; }
    public String getPrivateKeyPem() { return privateKeyPem; }
    public String getPublicKeyPem() { return publicKeyPem; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getRetireAfter() { return retireAfter; }
}
