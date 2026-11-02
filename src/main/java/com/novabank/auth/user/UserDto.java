package com.novabank.auth.user;

import java.time.Instant;

/** Public view of a user. The password hash never leaves the service. */
public record UserDto(Long id, String email, String fullName, String phone, Role role, UserStatus status,
                      Instant createdAt, Instant lastLoginAt) {

    public static UserDto from(User u) {
        return new UserDto(u.getId(), u.getEmail(), u.getFullName(), u.getPhone(), u.getRole(), u.getStatus(),
                u.getCreatedAt(), u.getLastLoginAt());
    }
}
