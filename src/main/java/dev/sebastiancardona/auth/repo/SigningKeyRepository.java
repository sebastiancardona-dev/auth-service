package dev.sebastiancardona.auth.repo;

import dev.sebastiancardona.auth.domain.SigningKey;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SigningKeyRepository extends JpaRepository<SigningKey, UUID> {
    List<SigningKey> findAllByOrderByCreatedAtDesc();
}
