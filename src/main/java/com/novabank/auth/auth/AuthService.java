package com.novabank.auth.auth;

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
        User user = users.findByEmailIgnoreCase(req.email().trim())
                .filter(u -> passwordEncoder.matches(req.password(), u.getPasswordHash()))
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Invalid email or password"));
        if (user.getStatus() == UserStatus.LOCKED) {
            throw new ApiException(HttpStatus.FORBIDDEN, "Your profile is locked. Please contact NovaBank support.");
        }
        user.setLastLoginAt(Instant.now());
        log.info("User {} logged in", user.getId());
        return new AuthResponse(tokens.issue(user), tokens.expiresInSeconds(), UserDto.from(user));
    }

    public AuthResponse register(RegisterRequest req) {
        String email = req.email().trim().toLowerCase();
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
        User user = find(userId);
        user.setFullName(req.fullName().trim());
        user.setPhone(req.phone());
        return UserDto.from(user);
    }

    @Transactional
    public void changePassword(Long userId, ChangePasswordRequest req) {
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
