package com.syntrace.service;

import com.syntrace.config.SynTraceProperties;
import com.syntrace.dto.auth.AuthResponse;
import com.syntrace.dto.auth.LoginRequest;
import com.syntrace.dto.auth.RefreshRequest;
import com.syntrace.dto.auth.RegisterRequest;
import com.syntrace.dto.auth.UserDTO;
import com.syntrace.entity.RefreshToken;
import com.syntrace.entity.Role;
import com.syntrace.entity.RoleName;
import com.syntrace.entity.User;
import com.syntrace.exception.ResourceNotFoundException;
import com.syntrace.mapper.UserMapper;
import com.syntrace.repository.RefreshTokenRepository;
import com.syntrace.repository.RoleRepository;
import com.syntrace.repository.UserRepository;
import com.syntrace.security.JwtTokenProvider;
import com.syntrace.security.SynTraceUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

import org.springframework.security.authentication.AuthenticationManager;

/**
 * Authentication, registration and refresh-token rotation.
 *
 * <p>Refresh tokens are opaque 256-bit random strings; only their SHA-256 hash is stored, so
 * a database copy cannot be replayed. Rotation is single-use: presenting a token issues a
 * new one and revokes the old, which makes token theft detectable.</p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int LOCK_THRESHOLD = 5;

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserMapper userMapper;
    private final AuditService auditService;
    private final SynTraceProperties properties;

    /**
     * Authenticates an analyst and issues credentials.
     *
     * @param request submitted credentials
     * @return access and refresh tokens plus the account projection
     */
    @Transactional
    public AuthResponse login(LoginRequest request) {
        try {
            var authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.identifier(), request.password()));
            SynTraceUserDetails principal = (SynTraceUserDetails) authentication.getPrincipal();

            User user = userRepository.findById(principal.getId())
                    .orElseThrow(() -> new ResourceNotFoundException("Account no longer exists"));
            user.registerSuccessfulLogin(Instant.now());
            userRepository.save(user);

            auditService.loginSuccess(user.getUsername());
            return issue(user, principal);
        } catch (AuthenticationException ex) {
            registerFailure(request.identifier());
            auditService.loginFailure(request.identifier(), ex.getMessage());
            throw new BadCredentialsException("Invalid username or password");
        }
    }

    /**
     * Provisions a new account. Administrator-only at the controller layer.
     *
     * @param request account details
     * @return the created account
     */
    @Transactional
    public UserDTO register(RegisterRequest request) {
        if (userRepository.findByUsernameIgnoreCase(request.username()).isPresent()) {
            throw new IllegalArgumentException("Username '" + request.username() + "' is already taken");
        }
        if (userRepository.findByEmailIgnoreCase(request.email()).isPresent()) {
            throw new IllegalArgumentException("Email '" + request.email() + "' is already registered");
        }

        RoleName roleName = request.role() == null ? RoleName.ANALYST : request.role();
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new ResourceNotFoundException("Role " + roleName + " is not provisioned"));

        User user = User.builder()
                .username(request.username())
                .email(request.email())
                .fullName(request.fullName())
                .department(request.department())
                .passwordHash(passwordEncoder.encode(request.password()))
                .enabled(true)
                .passwordChangedAt(Instant.now())
                .build();
        user.addRole(role);
        user = userRepository.save(user);

        auditService.record(com.syntrace.entity.AuditAction.USER_CREATED,
                com.syntrace.security.SecurityUtils.currentUsernameOrSystem(),
                user.getId(), "User", "SUCCESS", "Provisioned account with role " + roleName);
        log.info("Provisioned account {} with role {}", user.getUsername(), roleName);
        return userMapper.toDto(user);
    }

    /**
     * Rotates a refresh token.
     *
     * @param request the token presented by the console
     * @return freshly issued credentials
     */
    @Transactional
    public AuthResponse refresh(RefreshRequest request) {
        String presentedHash = hash(request.refreshToken());
        RefreshToken stored = refreshTokenRepository.findByTokenHash(presentedHash)
                .orElseThrow(() -> new BadCredentialsException("Unknown refresh token"));

        if (!stored.isActive()) {
            revokeAll(stored.getUser());
            throw new BadCredentialsException("Refresh token is expired or already used");
        }

        User user = stored.getUser();
        AuthResponse response = issue(user, new SynTraceUserDetails(user));
        stored.revoke(hash(response.refreshToken()));
        refreshTokenRepository.save(stored);

        auditService.record(com.syntrace.entity.AuditAction.TOKEN_REFRESH, user.getUsername(),
                user.getId(), "User", "SUCCESS", "Refresh token rotated");
        return response;
    }

    /**
     * Revokes every active refresh token for the caller.
     *
     * @param username account signing out
     */
    @Transactional
    public void logout(String username) {
        userRepository.findByUsernameIgnoreCase(username).ifPresent(this::revokeAll);
        auditService.logout(username);
    }

    /**
     * @param username authenticated principal
     * @return the account projection for the caller
     */
    @Transactional(readOnly = true)
    public UserDTO currentUser(String username) {
        return userRepository.findByUsernameIgnoreCase(username)
                .map(userMapper::toDto)
                .orElseThrow(() -> new ResourceNotFoundException("Account " + username + " does not exist"));
    }

    // ------------------------------------------------------------------ internals

    private AuthResponse issue(User user, SynTraceUserDetails principal) {
        String accessToken = jwtTokenProvider.generateAccessToken(principal);
        String refreshToken = newOpaqueToken();

        refreshTokenRepository.save(RefreshToken.builder()
                .user(user)
                .tokenHash(hash(refreshToken))
                .expiresAt(Instant.now().plusSeconds(
                        properties.getSecurity().getJwt().getRefreshTokenValidityDays() * 86_400L))
                .revoked(false)
                .build());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtTokenProvider.getAccessTokenValiditySeconds())
                .user(userMapper.toDto(user))
                .build();
    }

    private void revokeAll(User user) {
        refreshTokenRepository.findAllByUserAndRevokedFalse(user)
                .forEach(token -> {
                    token.revoke(null);
                    refreshTokenRepository.save(token);
                });
    }

    private void registerFailure(String identifier) {
        userRepository.findByUsernameOrEmail(identifier).ifPresent(user -> {
            user.registerFailedLogin(LOCK_THRESHOLD);
            userRepository.save(user);
        });
    }

    private String newOpaqueToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hash(String token) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable in this JVM", ex);
        }
    }
}
