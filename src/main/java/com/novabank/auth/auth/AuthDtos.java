package com.novabank.auth.auth;

import com.novabank.auth.user.UserDto;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public final class AuthDtos {

    private AuthDtos() {
    }

    public record LoginRequest(
            @NotBlank @Email String email,
            @NotBlank String password) {

        /** Never print the password, even by accident in a log line. */
        @Override
        public String toString() {
            return "LoginRequest[email=" + email + ", password=****]";
        }
    }

    public record RegisterRequest(
            @NotBlank @Size(max = 120) String fullName,
            @NotBlank @Email @Size(max = 120) String email,
            @Pattern(regexp = "^[+0-9 ()-]{7,20}$", message = "Enter a valid phone number") String phone,
            @NotBlank @Pattern(regexp = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[^A-Za-z0-9]).{8,64}$",
                    message = "Use 8+ characters with upper, lower, number and symbol") String password) {

        @Override
        public String toString() {
            return "RegisterRequest[fullName=" + fullName + ", email=" + email + ", phone=" + phone + ", password=****]";
        }
    }

    public record UpdateProfileRequest(
            @NotBlank @Size(max = 120) String fullName,
            @Pattern(regexp = "^[+0-9 ()-]{7,20}$", message = "Enter a valid phone number") String phone) {
    }

    public record ChangePasswordRequest(
            @NotBlank String currentPassword,
            @NotBlank @Pattern(regexp = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[^A-Za-z0-9]).{8,64}$",
                    message = "Use 8+ characters with upper, lower, number and symbol") String newPassword) {

        @Override
        public String toString() {
            return "ChangePasswordRequest[currentPassword=****, newPassword=****]";
        }
    }

    public record AuthResponse(String token, long expiresInSeconds, UserDto user) {
    }
}
