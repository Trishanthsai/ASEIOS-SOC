package com.syntrace.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Read-only helpers for resolving the current principal outside of controllers.
 */
public final class SecurityUtils {

    private SecurityUtils() {
    }

    public static Optional<SynTraceUserDetails> currentPrincipal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof SynTraceUserDetails details)) {
            return Optional.empty();
        }
        return Optional.of(details);
    }

    public static Optional<UUID> currentUserId() {
        return currentPrincipal().map(SynTraceUserDetails::getId);
    }

    public static String currentUsernameOrSystem() {
        return currentPrincipal().map(SynTraceUserDetails::getUsername).orElse("system");
    }

    public static Set<String> currentAuthorities() {
        return currentPrincipal()
                .map(p -> p.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet()))
                .orElse(Set.of());
    }

    public static boolean hasAuthority(String authority) {
        return currentAuthorities().contains(authority);
    }
}
