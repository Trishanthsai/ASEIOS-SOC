package com.syntrace.normalizer;

import com.syntrace.entity.EventType;
import com.syntrace.entity.LogSourceType;
import com.syntrace.entity.Severity;
import com.syntrace.parser.NormalizedEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * MODULE 2 - Normalizer.
 *
 * <p>Collapses every vendor dialect into the single {@link EventType} taxonomy so the
 * detection engine can be written once instead of once per product:</p>
 *
 * <pre>
 * Windows 4625            -> AUTHENTICATION_FAILURE
 * Linux "authentication failure" -> AUTHENTICATION_FAILURE
 * Firewall "Denied access" -> FIREWALL_DENY (blocked connection)
 * </pre>
 */
@Slf4j
@Component
public class LogNormalizer {

    /** Windows Security / System event identifier to canonical type. */
    private static final Map<String, EventType> WINDOWS_EVENT_IDS = Map.ofEntries(
            Map.entry("4624", EventType.AUTHENTICATION_SUCCESS),
            Map.entry("4625", EventType.AUTHENTICATION_FAILURE),
            Map.entry("4634", EventType.AUTHENTICATION_SUCCESS),
            Map.entry("4648", EventType.AUTHENTICATION_SUCCESS),
            Map.entry("4672", EventType.PRIVILEGE_ESCALATION),
            Map.entry("4673", EventType.PRIVILEGE_ESCALATION),
            Map.entry("4688", EventType.PROCESS_CREATION),
            Map.entry("4697", EventType.SERVICE_INSTALLED),
            Map.entry("4698", EventType.SCHEDULED_TASK_CREATED),
            Map.entry("4699", EventType.SCHEDULED_TASK_CREATED),
            Map.entry("4702", EventType.SCHEDULED_TASK_CREATED),
            Map.entry("4719", EventType.CONFIGURATION_CHANGE),
            Map.entry("4720", EventType.CONFIGURATION_CHANGE),
            Map.entry("4732", EventType.PRIVILEGE_ESCALATION),
            Map.entry("4740", EventType.ACCOUNT_LOCKOUT),
            Map.entry("4776", EventType.AUTHENTICATION_FAILURE),
            Map.entry("1102", EventType.AUDIT_LOG_CLEARED),
            Map.entry("104", EventType.AUDIT_LOG_CLEARED),
            Map.entry("5140", EventType.SMB_CONNECTION),
            Map.entry("5145", EventType.SMB_CONNECTION),
            Map.entry("5156", EventType.NETWORK_CONNECTION),
            Map.entry("5157", EventType.FIREWALL_DENY),
            Map.entry("4663", EventType.FILE_ACCESS),
            Map.entry("4656", EventType.FILE_ACCESS),
            Map.entry("4660", EventType.FILE_DELETED),
            Map.entry("2003", EventType.SECURITY_TOOL_DISABLED),
            Map.entry("5001", EventType.SECURITY_TOOL_DISABLED),
            Map.entry("5007", EventType.CONFIGURATION_CHANGE),
            Map.entry("1116", EventType.ANTIVIRUS_ALERT),
            Map.entry("1117", EventType.ANTIVIRUS_ALERT),
            Map.entry("6416", EventType.USB_DEVICE_CONNECTED),
            Map.entry("2100", EventType.USB_DEVICE_CONNECTED),
            Map.entry("2102", EventType.USB_DEVICE_DISCONNECTED),
            Map.entry("6005", EventType.SYSTEM_START),
            Map.entry("6006", EventType.SYSTEM_SHUTDOWN));

    /** Sysmon operational channel identifier to canonical type. */
    private static final Map<String, EventType> SYSMON_EVENT_IDS = Map.ofEntries(
            Map.entry("1", EventType.PROCESS_CREATION),
            Map.entry("3", EventType.NETWORK_CONNECTION),
            Map.entry("6", EventType.SERVICE_INSTALLED),
            Map.entry("7", EventType.PROCESS_CREATION),
            Map.entry("8", EventType.PRIVILEGE_ESCALATION),
            Map.entry("10", EventType.PRIVILEGE_ESCALATION),
            Map.entry("11", EventType.FILE_CREATED),
            Map.entry("12", EventType.REGISTRY_MODIFICATION),
            Map.entry("13", EventType.REGISTRY_MODIFICATION),
            Map.entry("14", EventType.REGISTRY_MODIFICATION),
            Map.entry("15", EventType.FILE_CREATED),
            Map.entry("17", EventType.NETWORK_CONNECTION),
            Map.entry("22", EventType.DNS_QUERY),
            Map.entry("23", EventType.FILE_DELETED),
            Map.entry("26", EventType.FILE_DELETED));

    private static final Pattern SCRIPT_HOST = Pattern.compile(
            "(?i)\\b(powershell(\\.exe)?|pwsh|cmd\\.exe|wscript|cscript|mshta|bash|sh|python\\d?)\\b");

    private static final Pattern ENCRYPTION_HINT = Pattern.compile(
            "(?i)(encrypt|\\.locked|\\.crypt|ransom|readme_to_decrypt|aes-256|bulk rename)");

    private static final Pattern USB_HINT = Pattern.compile(
            "(?i)(usb|removable (storage|device|disk)|mass storage|usbstor|new external device)");

    private static final Pattern DEFENDER_HINT = Pattern.compile(
            "(?i)(defender|real-?time protection|antivirus|antimalware).{0,40}(disabl|turn(ed)? off|stopp)"
                    + "|(?i)(disabl|turn(ed)? off|stopp).{0,40}(defender|real-?time protection|antivirus)");

    private static final Pattern PRIVILEGE_HINT = Pattern.compile(
            "(?i)(special privileges|privilege escalation|elevated token|added to (the )?(administrators|sudo|wheel)"
                    + "|session opened for user root|uid=0|runas|seDebugPrivilege)");

    private static final Pattern FAILED_LOGIN_HINT = Pattern.compile(
            "(?i)(authentication failure|failed password|failed to log on|logon failure|invalid user"
                    + "|access denied for user|login failed)");

    private static final Pattern SUCCESS_LOGIN_HINT = Pattern.compile(
            "(?i)(accepted password|session opened|an account was successfully logged on|login successful)");

    private static final Pattern DENY_HINT = Pattern.compile(
            "(?i)\\b(deny|denied|drop|dropped|block(ed)?|reject(ed)?)\\b");

    private static final Pattern ALLOW_HINT = Pattern.compile(
            "(?i)\\b(allow(ed)?|accept(ed)?|permit(ted)?|built|teardown)\\b");

    private static final Pattern SCHEDULED_TASK_HINT = Pattern.compile(
            "(?i)(scheduled task|schtasks|crontab|cron\\.d|systemd timer|at\\.exe)");

    private static final Pattern SMB_HINT = Pattern.compile(
            "(?i)(smb|\\\\\\\\[A-Za-z0-9._\\-]+\\\\[A-Za-z0-9$._\\-]+|admin\\$|ipc\\$|c\\$|port\\s*445)");

    private static final Pattern MASS_ACCESS_HINT = Pattern.compile(
            "(?i)(bulk (file )?(read|access)|mass file|enumerat(ed|ing) \\d+ files|\\d{3,} files)");

    private static final Pattern EXFIL_HINT = Pattern.compile(
            "(?i)(exfiltrat|outbound transfer|upload(ed)? \\d+|data transfer|large outbound)");

    private static final Pattern UNKNOWN_EXE_HINT = Pattern.compile(
            "(?i)(unsigned|unknown (executable|publisher)|no valid signature|untrusted binary)");

    /** Directories that legitimate signed software should not be executing from. */
    private static final List<String> SUSPICIOUS_PATHS = List.of(
            "\\appdata\\", "\\temp\\", "\\tmp\\", "/tmp/", "/dev/shm/", "\\downloads\\",
            "\\programdata\\", "\\users\\public\\", "\\recycle");

    /**
     * Applies the taxonomy to a batch of parsed events.
     *
     * @param events parser output
     * @return the same instances, enriched in place, with unusable rows removed
     */
    public List<NormalizedEvent> normalize(List<NormalizedEvent> events) {
        return events.stream()
                .map(this::normalize)
                .filter(event -> event.getTimestamp() != null)
                .toList();
    }

    /**
     * Applies the taxonomy to a single event.
     *
     * @param event parser output
     * @return the same instance, enriched
     */
    public NormalizedEvent normalize(NormalizedEvent event) {
        if (event.getTimestamp() == null) {
            event.setTimestamp(fallbackTimestamp(event));
        }
        if (event.getHostname() == null || event.getHostname().isBlank()) {
            event.setHostname("unknown-host");
        }
        if (event.getSourceType() == null) {
            event.setSourceType(LogSourceType.UNKNOWN);
        }
        if (event.getMessage() == null) {
            event.setMessage(event.getRawLog());
        }

        EventType type = classify(event);
        event.setEventType(type);
        event.setSeverity(severityFor(type, event));
        if (event.getAction() == null) {
            event.setAction(actionFor(type));
        }
        return event;
    }

    /**
     * Core mapping routine: event code first (deterministic), then message heuristics.
     *
     * @param event event to classify
     * @return canonical type, never {@code null}
     */
    private EventType classify(NormalizedEvent event) {
        String code = event.getEventCode();
        LogSourceType source = event.getSourceType();

        if (code != null) {
            EventType mapped = source == LogSourceType.SYSMON
                    ? SYSMON_EVENT_IDS.get(code)
                    : WINDOWS_EVENT_IDS.get(code);
            if (mapped != null) {
                return refine(mapped, event);
            }
        }

        String text = event.searchableText();

        if (USB_HINT.matcher(text).find()) {
            return text.contains("remov") && text.contains("disconnect")
                    ? EventType.USB_DEVICE_DISCONNECTED
                    : EventType.USB_DEVICE_CONNECTED;
        }
        if (DEFENDER_HINT.matcher(text).find()) {
            return EventType.SECURITY_TOOL_DISABLED;
        }
        if (ENCRYPTION_HINT.matcher(text).find()) {
            return EventType.FILE_ENCRYPTED;
        }
        if (FAILED_LOGIN_HINT.matcher(text).find()) {
            return EventType.AUTHENTICATION_FAILURE;
        }
        if (PRIVILEGE_HINT.matcher(text).find()) {
            return EventType.PRIVILEGE_ESCALATION;
        }
        if (SUCCESS_LOGIN_HINT.matcher(text).find()) {
            return EventType.AUTHENTICATION_SUCCESS;
        }
        if (SCHEDULED_TASK_HINT.matcher(text).find()) {
            return EventType.SCHEDULED_TASK_CREATED;
        }
        if (MASS_ACCESS_HINT.matcher(text).find()) {
            return EventType.MASS_FILE_ACCESS;
        }
        if (SMB_HINT.matcher(text).find()) {
            return EventType.SMB_CONNECTION;
        }
        if (source == LogSourceType.FIREWALL || event.getAction() != null) {
            String action = event.getAction() == null ? text : event.getAction();
            if (DENY_HINT.matcher(action).find()) {
                return EXFIL_HINT.matcher(text).find() ? EventType.FIREWALL_DENY : EventType.FIREWALL_DENY;
            }
            if (ALLOW_HINT.matcher(action).find()) {
                return EventType.FIREWALL_ALLOW;
            }
        }
        if (EXFIL_HINT.matcher(text).find()) {
            return EventType.DATA_TRANSFER;
        }
        if (UNKNOWN_EXE_HINT.matcher(text).find() || executedFromSuspiciousPath(event)) {
            return EventType.UNKNOWN_EXECUTABLE;
        }
        if (SCRIPT_HOST.matcher(text).find()) {
            return EventType.SCRIPT_EXECUTION;
        }
        if (event.getProcessName() != null) {
            return EventType.PROCESS_CREATION;
        }
        return EventType.OTHER;
    }

    /**
     * Second pass over code-derived types: a {@code 4688} process creation is really a
     * script execution when the created image is a shell, and an unknown executable when
     * it lives in a user-writable directory.
     */
    private EventType refine(EventType mapped, NormalizedEvent event) {
        if (mapped != EventType.PROCESS_CREATION) {
            return mapped;
        }
        if (executedFromSuspiciousPath(event) || UNKNOWN_EXE_HINT.matcher(event.searchableText()).find()) {
            return EventType.UNKNOWN_EXECUTABLE;
        }
        String process = event.getProcessName() == null ? "" : event.getProcessName();
        if (SCRIPT_HOST.matcher(process).find()) {
            return EventType.SCRIPT_EXECUTION;
        }
        return EventType.PROCESS_CREATION;
    }

    private boolean executedFromSuspiciousPath(NormalizedEvent event) {
        String path = event.getFilePath() != null ? event.getFilePath() : event.getCommandLine();
        if (path == null) {
            return false;
        }
        String lower = path.toLowerCase();
        boolean executable = lower.contains(".exe") || lower.contains(".dll") || lower.contains(".scr")
                || lower.contains(".ps1") || lower.contains(".bat") || lower.contains(".sh");
        return executable && SUSPICIOUS_PATHS.stream().anyMatch(lower::contains);
    }

    /**
     * Baseline severity per canonical type. Detection rules may raise it later.
     */
    private Severity severityFor(EventType type, NormalizedEvent event) {
        Severity base = switch (type) {
            case FILE_ENCRYPTED, SECURITY_TOOL_DISABLED, AUDIT_LOG_CLEARED -> Severity.CRITICAL;
            case PRIVILEGE_ESCALATION, UNKNOWN_EXECUTABLE, MASS_FILE_ACCESS, ANTIVIRUS_ALERT -> Severity.HIGH;
            case SCRIPT_EXECUTION, SCHEDULED_TASK_CREATED, SERVICE_INSTALLED, SMB_CONNECTION,
                 USB_DEVICE_CONNECTED, DATA_TRANSFER, ACCOUNT_LOCKOUT -> Severity.MEDIUM;
            case AUTHENTICATION_FAILURE, FIREWALL_DENY, REGISTRY_MODIFICATION, CONFIGURATION_CHANGE -> Severity.LOW;
            default -> Severity.INFO;
        };
        Severity parsed = event.getSeverity();
        return parsed != null && parsed.atLeast(base) ? parsed : base;
    }

    private String actionFor(EventType type) {
        return switch (type) {
            case AUTHENTICATION_FAILURE, FIREWALL_DENY -> "DENY";
            case AUTHENTICATION_SUCCESS, FIREWALL_ALLOW -> "ALLOW";
            default -> "OBSERVED";
        };
    }

    /**
     * Events without a recoverable timestamp are anchored to ingestion time so that they
     * remain visible in the timeline instead of silently vanishing.
     */
    private Instant fallbackTimestamp(NormalizedEvent event) {
        log.trace("No timestamp recovered for line {}; anchoring to ingest time", event.getLineNumber());
        return Instant.now();
    }
}
