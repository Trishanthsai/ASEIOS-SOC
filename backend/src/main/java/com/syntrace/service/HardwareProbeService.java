package com.syntrace.service;

import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.lang.management.ManagementFactory;
import com.sun.management.OperatingSystemMXBean;

/**
 * Probes the host system resources (CPU cores, RAM capacity, JVM memory)
 * and dynamically recommends performance profiles for local AI model inference.
 */
@Slf4j
@Service
public class HardwareProbeService {

    @Data
    @Builder
    public static class HardwareProfile {
        private int availableProcessors;
        private double totalPhysicalMemoryGb;
        private double freePhysicalMemoryGb;
        private double jvmMaxMemoryMb;
        private double jvmUsedMemoryMb;
        private String recommendedProfile; // ULTRA_LOW_SPEC, BALANCED_CPU, HIGH_PERFORMANCE_GPU
        private String description;
    }

    public HardwareProfile probeSystem() {
        OperatingSystemMXBean osBean = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
        Runtime runtime = Runtime.getRuntime();

        int cores = osBean.getAvailableProcessors();
        double totalRamGb = osBean.getTotalMemorySize() / (1024.0 * 1024.0 * 1024.0);
        double freeRamGb = osBean.getFreeMemorySize() / (1024.0 * 1024.0 * 1024.0);
        double jvmMaxMb = runtime.maxMemory() / (1024.0 * 1024.0);
        double jvmUsedMb = (runtime.totalMemory() - runtime.freeMemory()) / (1024.0 * 1024.0);

        String profile;
        String desc;

        if (totalRamGb >= 16.0 && cores >= 8) {
            profile = "HIGH_PERFORMANCE_GPU";
            desc = "Hardware supports real-time streaming LLM inference with dedicated local GPU/multithreading.";
        } else if (totalRamGb >= 8.0) {
            profile = "BALANCED_CPU";
            desc = "Hardware supports 3B quantized local LLMs on CPU with moderate chunking.";
        } else {
            profile = "ULTRA_LOW_SPEC";
            desc = "Hardware optimized for instant deterministic template generation and low memory footprint.";
        }

        return HardwareProfile.builder()
                .availableProcessors(cores)
                .totalPhysicalMemoryGb(Math.round(totalRamGb * 100.0) / 100.0)
                .freePhysicalMemoryGb(Math.round(freeRamGb * 100.0) / 100.0)
                .jvmMaxMemoryMb(Math.round(jvmMaxMb * 10.0) / 10.0)
                .jvmUsedMemoryMb(Math.round(jvmUsedMb * 10.0) / 10.0)
                .recommendedProfile(profile)
                .description(desc)
                .build();
    }
}
