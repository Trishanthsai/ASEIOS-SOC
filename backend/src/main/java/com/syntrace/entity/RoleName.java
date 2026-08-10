package com.syntrace.entity;

/**
 * Role based access control identities.
 *
 * <ul>
 *   <li>{@code ADMIN} - full platform control, user management, rule management.</li>
 *   <li>{@code ANALYST} - upload evidence, run analysis, close incidents, export reports.</li>
 *   <li>{@code VIEWER} - read-only dashboard and report access.</li>
 * </ul>
 */
public enum RoleName {
    ADMIN,
    ANALYST,
    VIEWER
}
