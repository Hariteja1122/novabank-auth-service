package com.novabank.auth.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.novabank.auth.auth.AuthController;
import com.novabank.auth.auth.AuthService;
import com.novabank.auth.auth.LoginAttemptAuditAdvice;
import com.novabank.auth.auth.TokenService;
import com.novabank.auth.client.AccountClient;
import com.novabank.auth.common.GlobalExceptionHandler;
import com.novabank.auth.config.JwtProperties;
import com.novabank.auth.config.SecurityConfig;
import com.novabank.auth.user.Role;
import com.novabank.auth.user.User;
import com.novabank.auth.user.UserRepository;
import com.novabank.auth.user.UserStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import javax.crypto.SecretKey;
import java.util.Optional;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Runs the real controller, interceptor and advice, with only the database mocked. */
class LoginAuditTest {

    private static final String EMAIL = "john.carter@example.com";
    private static final String PASSWORD = "Password@123";
    private static final String WRONG_PASSWORD = "Hunter2-Secret!";

    private final UserRepository users = mock(UserRepository.class);
    private final AuditWriter writer = mock(AuditWriter.class);
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        JwtProperties props = new JwtProperties("test-secret-test-secret-test-secret-1234", "novabank-auth", 60);
        SecurityConfig config = new SecurityConfig();
        SecretKey key = config.jwtSecretKey(props);
        AuthService service = new AuthService(users, encoder, new TokenService(config.jwtEncoder(key), props),
                mock(AccountClient.class));
        mvc = MockMvcBuilders.standaloneSetup(new AuthController(service))
                .setControllerAdvice(new GlobalExceptionHandler(), new ProblemDetailAuditAdvice(),
                        new LoginAttemptAuditAdvice())
                .addMappedInterceptors(new String[]{"/api/**"}, new AuditInterceptor(writer, new ObjectMapper()))
                .build();
    }

    private User user(UserStatus status) {
        User u = new User();
        u.setId(3L);
        u.setEmail(EMAIL);
        u.setFullName("John Carter");
        u.setRole(Role.CUSTOMER);
        u.setStatus(status);
        u.setPasswordHash(encoder.encode(PASSWORD));
        return u;
    }

    private AuditLog login(String email, String password, int expectedStatus) throws Exception {
        String body = "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}";
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content(body)
                        .header("X-Forwarded-For", "203.0.113.7"))
                .andExpect(status().is(expectedStatus));
        ArgumentCaptor<AuditLog> row = ArgumentCaptor.forClass(AuditLog.class);
        verify(writer).write(row.capture());
        return row.getValue();
    }

    private static void assertNoPassword(AuditLog row, String password) {
        Stream.of(row.getActorEmail(), row.getAction(), row.getTargetType(), row.getTargetId(), row.getReason(),
                        row.getDetails(), row.getCorrelationId(), row.getSourceIp())
                .forEach(field -> {
                    if (field != null) {
                        assertThat(field).doesNotContain(password);
                        // No fragment either: no 4-character slice of the password may appear.
                        for (int i = 0; i + 4 <= password.length(); i++) {
                            assertThat(field).doesNotContain(password.substring(i, i + 4));
                        }
                    }
                });
    }

    @Test
    void wrongPasswordRecordsEmailAndReasonButNotThePassword() throws Exception {
        when(users.findByEmailIgnoreCase(EMAIL)).thenReturn(Optional.of(user(UserStatus.ACTIVE)));

        AuditLog row = login(EMAIL, WRONG_PASSWORD, 401);

        assertThat(row.getAction()).isEqualTo("LOGIN");
        assertThat(row.getOutcome()).isEqualTo(AuditLog.Outcome.FAILURE);
        assertThat(row.getHttpStatus()).isEqualTo(401);
        assertThat(row.getActorEmail()).isEqualTo(EMAIL);
        assertThat(row.getActorId()).isNull();
        assertThat(row.getTargetType()).isEqualTo("USER");
        assertThat(row.getTargetId()).isEqualTo("3");
        assertThat(row.getReason()).isEqualTo("Wrong password");
        assertThat(row.getSourceIp()).isEqualTo("203.0.113.7");
        assertNoPassword(row, WRONG_PASSWORD);
    }

    @Test
    void unknownEmailIsRecordedWithItsOwnReason() throws Exception {
        when(users.findByEmailIgnoreCase("nobody@example.com")).thenReturn(Optional.empty());

        AuditLog row = login("nobody@example.com", WRONG_PASSWORD, 401);

        assertThat(row.getActorEmail()).isEqualTo("nobody@example.com");
        assertThat(row.getReason()).isEqualTo("Unknown email");
        assertThat(row.getTargetId()).isNull();
        assertNoPassword(row, WRONG_PASSWORD);
    }

    @Test
    void lockedProfileIsRecorded() throws Exception {
        when(users.findByEmailIgnoreCase(EMAIL)).thenReturn(Optional.of(user(UserStatus.LOCKED)));

        AuditLog row = login(EMAIL, PASSWORD, 403);

        assertThat(row.getReason()).isEqualTo("Profile is locked");
        assertThat(row.getActorEmail()).isEqualTo(EMAIL);
        assertNoPassword(row, PASSWORD);
    }

    @Test
    void loginRejectedByValidationStillRecordsTheEmailTried() throws Exception {
        AuditLog row = login("not-an-email", WRONG_PASSWORD, 400);

        assertThat(row.getOutcome()).isEqualTo(AuditLog.Outcome.FAILURE);
        assertThat(row.getActorEmail()).isEqualTo("not-an-email");
        assertThat(row.getReason()).isEqualTo("Please correct the highlighted fields: email");
        assertNoPassword(row, WRONG_PASSWORD);
    }

    @Test
    void successfulLoginRecordsTheUser() throws Exception {
        when(users.findByEmailIgnoreCase(EMAIL)).thenReturn(Optional.of(user(UserStatus.ACTIVE)));

        AuditLog row = login(EMAIL, PASSWORD, 200);

        assertThat(row.getOutcome()).isEqualTo(AuditLog.Outcome.SUCCESS);
        assertThat(row.getActorId()).isEqualTo(3L);
        assertThat(row.getActorRole()).isEqualTo("CUSTOMER");
        assertThat(row.getReason()).isNull();
        assertNoPassword(row, PASSWORD);
    }
}
