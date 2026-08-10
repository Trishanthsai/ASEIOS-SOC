package com.syntrace.dto.auth;

import lombok.Builder;

/**
 * Issued credentials.
 *
 * @param accessToken  signed JWT for API calls
 * @param refreshToken opaque rotation token
 * @param tokenType    always {@code Bearer}
 * @param expiresIn    access token lifetime in seconds
 * @param user         the authenticated account
 */
@Builder
public record AuthResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresIn,
        UserDTO user) {
}
