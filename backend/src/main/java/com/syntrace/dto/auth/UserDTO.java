package com.syntrace.dto.auth;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/**
 * Safe projection of an account. Never carries the password hash.
 *
 * @param id          account identifier
 * @param username    login name
 * @param email       contact address
 * @param fullName    display name
 * @param department  owning team
 * @param roles       granted roles, e.g. {@code ROLE_ANALYST}
 * @param enabled     whether the account may sign in
 * @param lastLoginAt last successful authentication
 */
public record UserDTO(
        UUID id,
        String username,
        String email,
        String fullName,
        String department,
        Set<String> roles,
        boolean enabled,
        Instant lastLoginAt) {
}
