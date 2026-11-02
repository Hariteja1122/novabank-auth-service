package com.novabank.auth.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * JWT settings shared by every NovaBank service. The secret must be the same value
 * in all services because tokens are signed with HMAC SHA-256.
 */
@Validated
@ConfigurationProperties(prefix = "novabank.security.jwt")
public record JwtProperties(
        @NotBlank @Size(min = 32, message = "JWT secret must be at least 32 characters") String secret,
        @NotBlank String issuer,
        @Min(5) long expiryMinutes) {
}
