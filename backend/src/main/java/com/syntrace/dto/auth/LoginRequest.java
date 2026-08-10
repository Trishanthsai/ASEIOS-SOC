package com.syntrace.dto.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Credentials submitted at {@code POST /api/auth/login}.
 *
 * @param identifier username or email address
 * @param password   plaintext password, never logged or persisted
 */
public record LoginRequest(
        @NotBlank(message = "Username or email is required")
        @Size(max = 190)
        String identifier,

        @NotBlank(message = "Password is required")
        @Size(max = 128)
        String password) {
}
