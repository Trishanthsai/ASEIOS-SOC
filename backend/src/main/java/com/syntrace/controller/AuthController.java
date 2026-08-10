package com.syntrace.controller;

import com.syntrace.dto.auth.AuthResponse;
import com.syntrace.dto.auth.LoginRequest;
import com.syntrace.dto.auth.RefreshRequest;
import com.syntrace.dto.auth.RegisterRequest;
import com.syntrace.dto.auth.UserDTO;
import com.syntrace.security.SynTraceUserDetails;
import com.syntrace.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Authentication API: login, administrator-driven registration, refresh and logout.
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "JWT issuance and refresh token rotation")
public class AuthController {

    private final AuthService authService;

    /**
     * @param request submitted credentials
     * @return issued tokens
     */
    @PostMapping("/login")
    @Operation(summary = "Authenticate and receive an access and refresh token")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    /**
     * @param request account details
     * @return the provisioned account
     */
    @PostMapping("/register")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Provision a new analyst account")
    public ResponseEntity<UserDTO> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    /**
     * @param request presented refresh token
     * @return rotated credentials
     */
    @PostMapping("/refresh")
    @Operation(summary = "Rotate a refresh token")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        return ResponseEntity.ok(authService.refresh(request));
    }

    /**
     * @param principal authenticated caller
     * @return empty response once every refresh token is revoked
     */
    @PostMapping("/logout")
    @Operation(summary = "Revoke all refresh tokens for the caller")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal SynTraceUserDetails principal) {
        authService.logout(principal.getUsername());
        return ResponseEntity.noContent().build();
    }

    /**
     * @param principal authenticated caller
     * @return the caller's account projection
     */
    @GetMapping("/me")
    @Operation(summary = "Fetch the authenticated account")
    public ResponseEntity<UserDTO> me(@AuthenticationPrincipal SynTraceUserDetails principal) {
        return ResponseEntity.ok(authService.currentUser(principal.getUsername()));
    }
}
