package dev.sebastiancardona.auth.user;

import dev.sebastiancardona.auth.domain.User;
import dev.sebastiancardona.auth.repo.UserRepository;
import java.util.Optional;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class EcosystemUserDetailsService implements UserDetailsService {

    private final UserRepository users;

    public EcosystemUserDetailsService(UserRepository users) {
        this.users = users;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = users.findByEmail(email.toLowerCase().trim())
                .orElseThrow(() -> new UsernameNotFoundException("No user " + email));
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())
                .password(user.getPasswordHash())
                .disabled(user.isDisabled())
                .authorities(user.getGroups().stream()
                        .map(g -> new SimpleGrantedAuthority("GROUP_" + g))
                        .toList())
                .build();
    }

    @Transactional(readOnly = true)
    public Optional<User> findDomainUser(String email) {
        return users.findByEmail(email);
    }
}
