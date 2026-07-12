package dev.sebastiancardona.auth.repo;

import dev.sebastiancardona.auth.domain.InviteRedemption;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface InviteRedemptionRepository extends JpaRepository<InviteRedemption, Long> {
    List<InviteRedemption> findByInviteIdOrderByRedeemedAtDesc(UUID inviteId);
}
