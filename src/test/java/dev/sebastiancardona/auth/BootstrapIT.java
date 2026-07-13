package dev.sebastiancardona.auth;

import static org.assertj.core.api.Assertions.assertThat;

import dev.sebastiancardona.auth.config.BootstrapSeeder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

class BootstrapIT extends IntegrationTest {

    @Autowired RegisteredClientRepository clients;

    @Test
    void adminCliClientIsSeededAsPublicPkceLoopback() {
        RegisteredClient cli = clients.findByClientId(BootstrapSeeder.ADMIN_CLI_CLIENT_ID);
        assertThat(cli).isNotNull();
        assertThat(cli.getClientAuthenticationMethods())
                .containsExactly(ClientAuthenticationMethod.NONE);
        assertThat(cli.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(cli.getRedirectUris()).containsExactly(BootstrapSeeder.ADMIN_CLI_REDIRECT);
        assertThat(cli.getClientSecret()).isNull();
    }
}
