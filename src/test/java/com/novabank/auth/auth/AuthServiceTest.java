package com.novabank.auth.auth;

import com.novabank.auth.auth.AuthDtos.LoginRequest;
import com.novabank.auth.client.AccountClient;
import com.novabank.auth.common.ApiException;
import com.novabank.auth.config.JwtProperties;
import com.novabank.auth.config.SecurityConfig;
import com.novabank.auth.user.Role;
import com.novabank.auth.user.User;
import com.novabank.auth.user.UserRepository;
import com.novabank.auth.user.UserStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import javax.crypto.SecretKey;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthServiceTest {

    private final UserRepository users = mock(UserRepository.class);
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
    private final JwtProperties props = new JwtProperties("test-secret-test-secret-test-secret-1234", "novabank-auth", 60);
    private JwtDecoder decoder;
    private AuthService service;

    @BeforeEach
    void setUp() {
        SecurityConfig config = new SecurityConfig();
        SecretKey key = config.jwtSecretKey(props);
        decoder = config.jwtDecoder(key, props);
        TokenService tokens = new TokenService(config.jwtEncoder(key), props);
        service = new AuthService(users, encoder, tokens, mock(AccountClient.class));
    }

    private User user(UserStatus status) {
        User u = new User();
        u.setId(3L);
        u.setEmail("john.carter@example.com");
        u.setFullName("John Carter");
        u.setRole(Role.CUSTOMER);
        u.setStatus(status);
        u.setPasswordHash(encoder.encode("Password@123"));
        return u;
    }

    @Test
    void loginIssuesTokenWithRoleClaim() {
        when(users.findByEmailIgnoreCase("john.carter@example.com")).thenReturn(Optional.of(user(UserStatus.ACTIVE)));

        var response = service.login(new LoginRequest("john.carter@example.com", "Password@123"));

        Jwt jwt = decoder.decode(response.token());
        assertThat(jwt.getSubject()).isEqualTo("3");
        assertThat(jwt.getClaimAsString("role")).isEqualTo("CUSTOMER");
        assertThat(response.user().email()).isEqualTo("john.carter@example.com");
    }

    @Test
    void wrongPasswordIsUnauthorized() {
        when(users.findByEmailIgnoreCase("john.carter@example.com")).thenReturn(Optional.of(user(UserStatus.ACTIVE)));

        assertThatThrownBy(() -> service.login(new LoginRequest("john.carter@example.com", "nope")))
                .isInstanceOf(ApiException.class)
                .extracting(e -> ((ApiException) e).getStatus())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void lockedUserCannotLogIn() {
        when(users.findByEmailIgnoreCase("john.carter@example.com")).thenReturn(Optional.of(user(UserStatus.LOCKED)));

        assertThatThrownBy(() -> service.login(new LoginRequest("john.carter@example.com", "Password@123")))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("locked");
    }
}
