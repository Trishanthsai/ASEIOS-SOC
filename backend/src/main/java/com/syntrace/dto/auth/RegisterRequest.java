package com.syntrace.dto.auth;

import com.syntrace.entity.RoleName;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Account provisioning payload. Administrators only - an isolated network has no
 * self-service signup.
 *
 * @param username   unique login name
 * @param email      contact address
 * @param fullName   display name
 * @param department owning team
 * @param password   initial password, must be rotated on first login
 * @param role       role to grant, defaults to {@code ANALYST} when omitted
 */
public record RegisterRequest(
        @NotBlank @Size(min = 3, max = 60)
        @Pattern(regexp = "^[A-Za-z0-9._-]+$", message = "Username may contain letters, digits, dot, underscore and hyphen")
        String username,

        @NotBlank @Email @Size(max = 190)
        String email,

        @NotBlank @Size(max = 190)
        String fullName,

        @Size(max = 120)
        String department,

        @NotBlank
        @Size(min = 12, max = 128, message = "Passwords must be at least 12 characters")
        String password,

        RoleName role) {
}
