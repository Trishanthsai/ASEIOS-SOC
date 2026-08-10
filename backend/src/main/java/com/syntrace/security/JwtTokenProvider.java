package com.syntrace.security;

import com.syntrace.config.SynTraceProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Issues and validates HS512 signed access tokens. Refresh tokens are opaque and
 * are handled by {@code RefreshTokenService} (Phase 2).
 */
@Slf4j
@Component
public class JwtTokenProvider {

    public static final String CLAIM_ROLES = "roles";
    public static final String CLAIM_USER_ID = "uid";
    public static final String CLAIM_EMAIL = "email";
    public static final String CLAIM_TOKEN_TYPE = "typ";
    public static final String TOKEN_TYPE_ACCESS = "access";

    private final SecretKey signingKey;
    private final String issuer;
    private final Duration accessTokenValidity;

    public JwtTokenProvider(SynTraceProperties properties) {
        SynTraceProperties.Jwt jwt = properties.getSecurity().getJwt();
        this.signingKey = buildKey(jwt.getSecret());
        this.issuer = jwt.getIssuer();
        this.accessTokenValidity = Duration.ofMinutes(jwt.getAccessTokenValidityMinutes());
    }

    private static SecretKey buildKey(String configuredSecret) {
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(configuredSecret);
        } catch (IllegalArgumentException ex) {
            keyBytes = configuredSecret.getBytes(StandardCharsets.UTF_8);
        }
        if (keyBytes.length < 64) {
            throw new IllegalStateException(
                    "syntrace.security.jwt.secret must decode to at least 64 bytes for HS512");
        }
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateAccessToken(SynTraceUserDetails principal) {
        Instant now = Instant.now();
        Instant expiry = now.plus(accessTokenValidity);
        List<String> roles = principal.getAuthorities().stream()
                .map(a -> a.getAuthority())
                .toList();

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .issuer(issuer)
                .subject(principal.getUsername())
                .issuedAt(Date.from(now))
                .notBefore(Date.from(now))
                .expiration(Date.from(expiry))
                .claims(Map.of(
                        CLAIM_USER_ID, principal.getId().toString(),
                        CLAIM_EMAIL, principal.getEmail() == null ? "" : principal.getEmail(),
                        CLAIM_ROLES, roles,
                        CLAIM_TOKEN_TYPE, TOKEN_TYPE_ACCESS))
                .signWith(signingKey, Jwts.SIG.HS512)
                .compact();
    }

    public Optional<Claims> parse(String token) {
        try {
            Jws<Claims> jws = Jwts.parser()
                    .verifyWith(signingKey)
                    .requireIssuer(issuer)
                    .build()
                    .parseSignedClaims(token);
            return Optional.of(jws.getPayload());
        } catch (ExpiredJwtException ex) {
            log.debug("Rejected expired JWT: {}", ex.getMessage());
        } catch (JwtException | IllegalArgumentException ex) {
            log.warn("Rejected invalid JWT: {}", ex.getMessage());
        }
        return Optional.empty();
    }

    public boolean isValid(String token) {
        return parse(token)
                .filter(claims -> TOKEN_TYPE_ACCESS.equals(claims.get(CLAIM_TOKEN_TYPE, String.class)))
                .isPresent();
    }

    public Optional<String> extractUsername(String token) {
        return parse(token).map(Claims::getSubject);
    }

    public long getAccessTokenValiditySeconds() {
        return accessTokenValidity.toSeconds();
    }
}
