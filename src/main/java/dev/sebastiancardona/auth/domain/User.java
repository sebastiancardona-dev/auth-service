package dev.sebastiancardona.auth.domain;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue
    private UUID id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "display_name", nullable = false)
    private String displayName;

    @Column(nullable = false)
    private String locale = "es";

    @Column(name = "disabled_at")
    private Instant disabledAt;

    @Column(name = "created_at", nullable = false, updatable = false, insertable = false)
    private Instant createdAt;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_groups", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "group_id")
    private Set<String> groups = new HashSet<>();

    protected User() {}

    public User(String email, String passwordHash, String displayName, String locale) {
        this.email = email;
        this.passwordHash = passwordHash;
        this.displayName = displayName;
        this.locale = locale;
    }

    public UUID getId() { return id; }
    public String getEmail() { return email; }
    public String getPasswordHash() { return passwordHash; }
    public String getDisplayName() { return displayName; }
    public String getLocale() { return locale; }
    public Instant getDisabledAt() { return disabledAt; }
    public Instant getCreatedAt() { return createdAt; }
    public Set<String> getGroups() { return groups; }

    public boolean isDisabled() { return disabledAt != null; }
    public void disable() { this.disabledAt = Instant.now(); }
    public void enable() { this.disabledAt = null; }
    public void setPasswordHash(String hash) { this.passwordHash = hash; }
    public void setDisplayName(String displayName) { this.displayName = displayName; }
}
