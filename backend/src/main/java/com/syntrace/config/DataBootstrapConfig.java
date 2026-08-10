package com.syntrace.config;

import com.syntrace.entity.Role;
import com.syntrace.entity.RoleName;
import com.syntrace.entity.User;
import com.syntrace.repository.RoleRepository;
import com.syntrace.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.EnumMap;
import java.util.Map;

/**
 * Seeds the RBAC role table and the break-glass administrator on first boot.
 * Air-gapped operators must rotate the bootstrap password immediately.
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class DataBootstrapConfig {

    private static final Map<RoleName, String> ROLE_DESCRIPTIONS = new EnumMap<>(Map.of(
            RoleName.ADMIN, "Full platform control: users, rules, retention and exports",
            RoleName.ANALYST, "Upload evidence, run investigations, triage incidents, export reports",
            RoleName.VIEWER, "Read-only access to dashboards, incidents and reports"
    ));

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SynTraceProperties properties;

    @Bean
    @Order(1)
    public ApplicationRunner synTraceBootstrapRunner() {
        return args -> bootstrap();
    }

    @Transactional
    public void bootstrap() {
        seedRoles();
        seedAdministrator();
    }

    private void seedRoles() {
        for (RoleName roleName : RoleName.values()) {
            if (!roleRepository.existsByName(roleName)) {
                roleRepository.save(Role.builder()
                        .name(roleName)
                        .description(ROLE_DESCRIPTIONS.get(roleName))
                        .build());
                log.info("Seeded role {}", roleName);
            }
        }
    }

    private void seedAdministrator() {
        SynTraceProperties.Bootstrap bootstrap = properties.getBootstrap();
        if (userRepository.existsByUsernameIgnoreCase(bootstrap.getAdminUsername())) {
            log.debug("Bootstrap administrator '{}' already present", bootstrap.getAdminUsername());
            return;
        }

        Role adminRole = roleRepository.findByName(RoleName.ADMIN)
                .orElseThrow(() -> new IllegalStateException("ADMIN role missing after seeding"));

        User admin = User.builder()
                .username(bootstrap.getAdminUsername())
                .email(bootstrap.getAdminEmail())
                .fullName("SynTrace Administrator")
                .department("Security Operations")
                .passwordHash(passwordEncoder.encode(bootstrap.getAdminPassword()))
                .enabled(true)
                .accountLocked(false)
                .passwordChangedAt(Instant.now())
                .build();
        admin.addRole(adminRole);

        userRepository.save(admin);
        log.warn("Bootstrap administrator '{}' created. ROTATE THE PASSWORD BEFORE OPERATIONAL USE.",
                bootstrap.getAdminUsername());
    }
}
