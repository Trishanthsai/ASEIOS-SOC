package com.syntrace.entity;

/**
 * Origin of an ingested evidence file, resolved by the parser strategy selector.
 */
public enum LogSourceType {
    WINDOWS_EVENT,
    SYSMON,
    LINUX_SYSLOG,
    LINUX_AUTH,
    FIREWALL,
    GENERIC_CSV,
    GENERIC_JSON,
    UNKNOWN
}
