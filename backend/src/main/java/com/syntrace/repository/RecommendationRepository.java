package com.syntrace.repository;

import com.syntrace.entity.Recommendation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface RecommendationRepository extends JpaRepository<Recommendation, UUID> {

    List<Recommendation> findAllByIncidentId(UUID incidentId);

    long countByIncidentIdAndCompletedFalse(UUID incidentId);
}
