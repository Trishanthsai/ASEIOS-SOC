package com.syntrace.detection;

import com.syntrace.entity.Severity;
import com.syntrace.entity.Threat;

import java.util.List;

/**
 * MODULE 3 - reusable detection rule contract.
 *
 * <p>A rule is a self-contained Spring bean. It first answers {@code matches} cheaply and
 * only then produces {@link Threat} records through {@code detect}. Adding a new detection
 * never requires editing the engine.</p>
 */
public interface DetectionRule {

    /** Stable identifier, e.g. {@code SYN-R-001}. Persisted on every threat. */
    String ruleId();

    /** Analyst-facing rule name, e.g. {@code Removable Media Connected}. */
    String name();

    /** Baseline severity emitted by this rule. */
    Severity severity();

    /** MITRE ATT&amp;CK technique identifier, e.g. {@code T1059.001}. */
    String mitreTechnique();

    /** MITRE ATT&amp;CK technique name. */
    String mitreTechniqueName();

    /** MITRE ATT&amp;CK tactic, e.g. {@code Execution}. */
    String mitreTactic();

    /** Weighted contribution to the incident risk score. */
    int riskWeight();

    /** Rule description surfaced in the UI and in reports. */
    String description();

    /**
     * Cheap pre-check.
     *
     * @param context indexed evidence
     * @return {@code true} when the rule should run
     */
    boolean matches(DetectionContext context);

    /**
     * Produces one threat per affected host.
     *
     * @param context indexed evidence
     * @return detected threats, possibly empty
     */
    List<Threat> detect(DetectionContext context);

    /** Execution order; lower runs first. */
    default int order() {
        return 100;
    }
}
