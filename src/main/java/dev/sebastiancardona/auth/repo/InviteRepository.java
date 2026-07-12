package dev.sebastiancardona.auth.repo;

import dev.sebastiancardona.auth.domain.Invite;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;

public interface InviteRepository extends JpaRepository<Invite, UUID> {

    // redemption is a read-check-increment: lock the row so two concurrent
    // redeems of a last-use token can't both pass the check
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select i from Invite i where i.tokenHash = :tokenHash")
    Optional<Invite> findByTokenHashForUpdate(String tokenHash);

    Optional<Invite> findByTokenHash(String tokenHash);

    List<Invite> findAllByOrderByCreatedAtDesc();
}
