package com.syntrace.entity;

/**
 * Normalised severity scale shared by events, threats, incidents and reports.
 */
public enum Severity {

    INFO(1),
    LOW(3),
    MEDIUM(5),
    HIGH(8),
    CRITICAL(10);

    private final int weight;

    Severity(int weight) {
        this.weight = weight;
    }

    public int getWeight() {
        return weight;
    }

    public boolean atLeast(Severity other) {
        return this.weight >= other.weight;
    }

    public static Severity fromWeight(int weight) {
        if (weight >= CRITICAL.weight) {
            return CRITICAL;
        }
        if (weight >= HIGH.weight) {
            return HIGH;
        }
        if (weight >= MEDIUM.weight) {
            return MEDIUM;
        }
        if (weight >= LOW.weight) {
            return LOW;
        }
        return INFO;
    }
}
