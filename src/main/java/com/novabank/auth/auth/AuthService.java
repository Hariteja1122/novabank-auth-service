package com.novabank.auth.auth;

import com.novabank.auth.audit.Audit;
import com.novabank.auth.auth.AuthDtos.AuthResponse;
import com.novabank.auth.auth.AuthDtos.ChangePasswordRequest;
import com.novabank.auth.auth.AuthDtos.LoginRequest;
import com.novabank.auth.auth.AuthDtos.RegisterRequest;
import com.novabank.auth.auth.AuthDtos.UpdateProfileRequest;
import com.novabank.auth.client.AccountClient;
import com.novabank.auth.common.ApiException;
import com.novabank.auth.user.Role;
import com.novabank.auth.user.User;
import com.novabank.auth.user.UserDto;
import com.novabank.auth.user.UserRepository;
import com.novabank.auth.user.UserStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokens;
    private final AccountClient accountClient;

    public AuthService(UserRepository users, PasswordEncoder passwordEncoder, TokenService tokens,
                       AccountClient accountClient) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.tokens = tokens;
        this.accountClient = accountClient;
    }

    @Transactional
    public AuthResponse login(LoginRequest req) {
        String email = req.email().trim();
        Audit.attemptedEmail(email);
        // The client always gets the same message for unknown email and wrong password, so it
        // cannot probe which emails exist. The audit reason tells admins which one it was.
        User user = users.findByEmailIgnoreCase(email).orElse(null);
        if (user == null) {
            Audit.reason("Unknown email");
            throw invalidCredentials();
        }
        Audit.target("USER", user.getId());
        if (!passwordEncoder.matches(req.password(), user.getPasswordHash())) {
            Audit.reason("Wrong password");
            throw invalidCredentials();
        }
        if (user.getStatus() == UserStatus.LOCKED) {
            Audit.reason("Profile is locked");
            throw new ApiException(HttpStatus.FORBIDDEN, "Your profile is locked. Please contact NovaBank support.");
        }
        user.setLastLoginAt(Instant.now());
        Audit.actor(user.getId(), user.getRole().name(), user.getEmail());
        log.info("User {} logged in", user.getId());
        return new AuthResponse(tokens.issue(user), tokens.expiresInSeconds(), UserDto.from(user));
    }

    private static ApiException invalidCredentials() {
        return new ApiException(HttpStatus.UNAUTHORIZED, "Invalid email or password");
    }

    public AuthResponse register(RegisterRequest req) {
        String email = req.email().trim().toLowerCase();
        Audit.attemptedEmail(email);
        if (users.existsByEmailIgnoreCase(email)) {
            throw ApiException.conflict("An account with this email already exists");
        }
        User user = new User();
        user.setEmail(email);
        user.setFullName(req.fullName().trim());
        user.setPhone(req.phone());
        user.setRole(Role.CUSTOMER);
        user.setStatus(UserStatus.ACTIVE);
        user.setPasswordHash(passwordEncoder.encode(req.password()));
        user.setLastLoginAt(Instant.now());
        user = users.save(user);
        log.info("Registered customer {}", user.getId());
        Audit.actor(user.getId(), user.getRole().name(), user.getEmail());
        Audit.target("USER", user.getId());

        // Every new customer starts with an empty checking account. Registration still
        // succeeds if account-service is down; an admin can open the account later.
        accountClient.openDefaultAccount(user.getId(), user.getFullName());

        return new AuthResponse(tokens.issue(user), tokens.expiresInSeconds(), UserDto.from(user));
    }

    public UserDto me(Long userId) {
        return UserDto.from(find(userId));
    }

    @Transactional
    public UserDto updateProfile(Long userId, UpdateProfileRequest req) {
        Audit.target("USER", userId);
        User user = find(userId);
        String fullName = req.fullName().trim();
        // Names of the changed fields only. Values (name, phone) stay out of the audit log.
        var changed = new java.util.ArrayList<String>();
        if (!fullName.equals(user.getFullName())) {
            changed.add("fullName");
        }
        if (!java.util.Objects.equals(req.phone(), user.getPhone())) {
            changed.add("phone");
        }
        Audit.detail("changedFields", changed.isEmpty() ? "none" : String.join(",", changed));
        user.setFullName(fullName);
        user.setPhone(req.phone());
        return UserDto.from(user);
    }

    @Transactional
    public void changePassword(Long userId, ChangePasswordRequest req) {
        Audit.target("USER", userId);
        User user = find(userId);
        if (!passwordEncoder.matches(req.currentPassword(), user.getPasswordHash())) {
            throw ApiException.badRequest("Current password is incorrect");
        }
        user.setPasswordHash(passwordEncoder.encode(req.newPassword()));
    }

    private User find(Long id) {
        return users.findById(id).orElseThrow(() -> ApiException.notFound("User not found"));
    }
}
