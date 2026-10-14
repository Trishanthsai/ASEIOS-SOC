import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Navbar } from "@/components/landing/Navbar";
import { Hero } from "@/components/landing/Hero";
import { WhySection } from "@/components/landing/WhySection";
import { BreakthroughDefenseSection } from "@/components/landing/BreakthroughDefenseSection";
import { ArchitectureSection } from "@/components/landing/ArchitectureSection";
import { PipelineSection } from "@/components/landing/PipelineSection";
import { CapabilitiesSection } from "@/components/landing/CapabilitiesSection";
import { AttackStoryShowcase } from "@/components/landing/AttackStoryShowcase";
import { AboutSection } from "@/components/landing/AboutSection";
import { Footer } from "@/components/landing/Footer";

import { TacticalContainmentModal } from "@/components/TacticalContainmentModal";
import { AttackSimulatorModal } from "@/components/AttackSimulatorModal";
import { DeceptionCanaryGrid } from "@/components/DeceptionCanaryGrid";
import { CommercialRoiCalculator } from "@/components/CommercialRoiCalculator";
import { OpticalDataDiodeModal } from "@/components/OpticalDataDiodeModal";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "ASEIOS-SOC — Offline Intelligence for Air-Gapped Security" },
      {
        name: "description",
        content:
          "Offline AI-Powered Security Operations Center for Air-Gapped and Isolated Defense Enclaves.",
      },
    ],
  }),
  component: LandingPage,
});

export function LandingPage() {
  // Breakthrough Feature Modals State
  const [showContainmentModal, setShowContainmentModal] = useState(false);
  const [showSimulatorModal, setShowSimulatorModal] = useState(false);
  const [showCanaryModal, setShowCanaryModal] = useState(false);
  const [showRoiModal, setShowRoiModal] = useState(false);
  const [showDiodeModal, setShowDiodeModal] = useState(false);

  // Containment execution simulation state
  const [isContained, setIsContained] = useState(false);

  // Simulated attack / canary tripwire notification banner
  const [recentActionNotice, setRecentActionNotice] = useState<{
    title: string;
    description: string;
  } | null>(null);

  const handleExecuteContainment = () => {
    setIsContained(true);
    setRecentActionNotice({
      title: "TACTICAL SOAR MICRO-CONTAINMENT EXECUTED",
      description:
        "Sub-second host isolation initiated on WIN-HOST-DRDO-14. Kerberos session revoked & kernel LAN egress blocked in 412ms.",
    });
  };

  const handleInjectAttack = (attackName: string, rawLogs: string[]) => {
    setShowSimulatorModal(false);
    setRecentActionNotice({
      title: `ATTACK SIMULATION INJECTED: ${attackName}`,
      description: `Generated ${rawLogs.length} high-fidelity events into the enclave telemetry pipeline. Launch SOC Console to triage.`,
    });
  };

  const handleTriggerTripwire = (canaryName: string) => {
    setShowCanaryModal(false);
    setRecentActionNotice({
      title: `DECEPTION CANARY TRIPPED: ${canaryName}`,
      description:
        "Zero-false-positive alert registered. Mathematical proof of unauthorized enclave reconnaissance. View in Console.",
    });
  };

  return (
    <div className="min-h-screen bg-[#030610] text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-white">
      <Navbar />

      {/* Global Interactive Action Banner (if a modal action was triggered) */}
      {recentActionNotice && (
        <div className="sticky top-14 z-40 bg-gradient-to-r from-cyan-950 via-slate-900 to-indigo-950 border-b border-cyan-500/50 px-4 py-2.5 text-xs font-mono text-cyan-200 flex flex-wrap items-center justify-between gap-3 shadow-md animate-in fade-in">
          <div className="flex items-center gap-2">
            <span className="size-2 rounded-full bg-cyan-400 animate-ping shrink-0" />
            <strong className="text-white font-bold">{recentActionNotice.title}:</strong>
            <span className="text-slate-300 font-sans">{recentActionNotice.description}</span>
          </div>
          <div className="flex items-center gap-2">
            <a
              href="/console"
              className="px-2.5 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded font-bold uppercase tracking-wider text-[10px] transition-colors"
            >
              Investigate in Console &rarr;
            </a>
            <button
              onClick={() => setRecentActionNotice(null)}
              className="text-slate-400 hover:text-white px-1 text-sm font-bold cursor-pointer"
            >
              &times;
            </button>
          </div>
        </div>
      )}

      <main className="flex-1">
        <Hero
          onOpenSimulator={() => setShowSimulatorModal(true)}
          onOpenRoi={() => setShowRoiModal(true)}
          onOpenCanary={() => setShowCanaryModal(true)}
        />
        <WhySection />
        <BreakthroughDefenseSection
          onOpenContainment={() => setShowContainmentModal(true)}
          onOpenSimulator={() => setShowSimulatorModal(true)}
          onOpenCanary={() => setShowCanaryModal(true)}
          onOpenRoi={() => setShowRoiModal(true)}
          onOpenDiode={() => setShowDiodeModal(true)}
        />
        <ArchitectureSection />
        <PipelineSection />
        <CapabilitiesSection />
        <AttackStoryShowcase />
        <AboutSection />
      </main>

      <Footer />

      {/* Interactive Breakthrough Feature Modals */}
      <TacticalContainmentModal
        isOpen={showContainmentModal}
        onClose={() => setShowContainmentModal(false)}
        targetHost="WIN-HOST-DRDO-14"
        isContained={isContained}
        onExecuteContainment={handleExecuteContainment}
      />

      <AttackSimulatorModal
        isOpen={showSimulatorModal}
        onClose={() => setShowSimulatorModal(false)}
        onInjectAttack={handleInjectAttack}
      />

      <DeceptionCanaryGrid
        isOpen={showCanaryModal}
        onClose={() => setShowCanaryModal(false)}
        onTriggerTripwire={handleTriggerTripwire}
      />

      <CommercialRoiCalculator isOpen={showRoiModal} onClose={() => setShowRoiModal(false)} />

      <OpticalDataDiodeModal
        isOpen={showDiodeModal}
        onClose={() => setShowDiodeModal(false)}
        evidenceHash="8f4b2b1a9e34c718a22d561e44f801bc3d2e99a11f54d68e7b99c012fa3829dc"
        incidentId="AES-2026-8941"
      />
    </div>
  );
}
