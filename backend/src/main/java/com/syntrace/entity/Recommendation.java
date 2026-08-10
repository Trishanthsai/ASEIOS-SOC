package com.syntrace.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

/**
 * A containment or remediation action proposed by the AI service for an incident.
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString(callSuper = true, of = {"action", "target", "priority"})
@Entity
@Table(name = "recommendations", indexes = {
        @Index(name = "idx_recommendations_incident", columnList = "incident_id")
})
public class Recommendation extends BaseEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "incident_id", nullable = false,
            foreignKey = @ForeignKey(name = "fk_recommendations_incident"))
    private Incident incident;

    @Column(name = "action", nullable = false, length = 255)
    private String action;

    @Column(name = "target", length = 255)
    private String target;

    @Enumerated(EnumType.STRING)
    @Column(name = "priority", nullable = false, length = 16)
    private Severity priority;

    @Column(name = "owner_team", length = 120)
    private String ownerTeam;

    @Column(name = "sla_hours")
    private Integer slaHours;

    @Lob
    @Column(name = "detail")
    private String detail;

    @Builder.Default
    @Column(name = "completed", nullable = false)
    private boolean completed = false;
}
