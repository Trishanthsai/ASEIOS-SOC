package com.syntrace.dto.auth;

import jakarta.validation.constraints.NotBlank;

/**
 * Token rotation payload.
 *
 * @param refreshToken opaque refresh token issued at login
 */
public record RefreshRequest(
        @NotBlank(message = "A refresh token is required")
        String refreshToken) {
}
