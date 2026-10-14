import React, { useState } from "react";
import { Link } from "@tanstack/react-router";
import {
  ShieldAlert,
  Crosshair,
  Radio,
  Calculator,
  Radar,
  ArrowRight,
  Terminal,
} from "lucide-react";
import { ScrollReveal } from "@/components/ui/ScrollReveal";

interface BreakthroughDefenseSectionProps {
  onOpenContainment: () => void;
  onOpenSimulator: () => void;
  onOpenCanary: () => void;
  onOpenRoi: () => void;
  onOpenDiode: () => void;
}

export function BreakthroughDefenseSection({
  onOpenContainment,
  onOpenSimulator,
  onOpenCanary,
  onOpenRoi,
  onOpenDiode,
}: BreakthroughDefenseSectionProps) {
  const [activeTab, setActiveTab] = useState<"all" | "defense" | "simulation" | "economics">("all");

  const technologies = [
    {
      id: "diode",
      category: "defense",
      title: "Bi-Directional Optical Data Diode",
      subtitle: "Zero-RF Physical Air-Gap Bridge",
      badge: "PHYSICAL LAYER ISOLATION",
      badgeColor: "border-purple-500/40 text-purple-300 bg-purple-950/30",
      icon: Radio,
      iconColor: "text-purple-400 bg-purple-950/40 border-purple-500/30",
      description:
        "Transfers cryptographically signed forensic evidence, threat telemetry, and offline signature packs across isolated physical boundaries using high-density animated optical QR/matrix streams—eliminating physical copper and radio frequency (RF) attack vectors.",
      metrics: [
        { label: "Hardware Egress", value: "0 B/s RF/Copper" },
        { label: "Matrix Stream", value: "4 FPS Animated High-Density" },
        { label: "Hash Validation", value: "SHA-256 Custody Sealed" },
      ],
      actionLabel: "View Optical Diode Stream",
      onAction: onOpenDiode,
    },
    {
      id: "containment",
      category: "defense",
      title: "Tactical SOAR Micro-Containment",
      subtitle: "Autonomous Local Host Isolation",
      badge: "SUB-SECOND RESPONSE",
      badgeColor: "border-rose-500/40 text-rose-300 bg-rose-950/30",
      icon: ShieldAlert,
      iconColor: "text-rose-400 bg-rose-950/40 border-rose-500/30",
      description:
        "Executes localized kernel-level containment without waiting for cloud playbooks. Injects zero-egress firewall blockades, terminates adversary PID trees (e.g. parent-child PowerShell exploits), revokes Kerberos TGT tickets, and triggers hardware USB media dismounts in under 415ms.",
      metrics: [
        { label: "Execution Time", value: "< 415 ms" },
        { label: "Isolation Protocol", value: "Kernel LAN Blockade" },
        { label: "Lateral Spill", value: "0% Propagation" },
      ],
      actionLabel: "Test SOAR Killswitch",
      onAction: onOpenContainment,
    },
    {
      id: "canary",
      category: "defense",
      title: "Deception Honey-Canary Grid",
      subtitle: "0% False-Positive Intrusion Tripwire",
      badge: "ZERO FALSE POSITIVES",
      badgeColor: "border-emerald-500/40 text-emerald-300 bg-emerald-950/30",
      icon: Radar,
      iconColor: "text-emerald-400 bg-emerald-950/40 border-emerald-500/30",
      description:
        "Plants high-value decoy honey-tokens inside the enclave—including fake nuclear encryption keyfiles (.kdbx), decoy domain admin accounts, simulated Modbus SCADA PLC ports (502), and canary registry keys. Any interaction is a mathematical guarantee of adversary activity.",
      metrics: [
        { label: "Decoy Vectors", value: "Files, Accounts, SCADA, Reg" },
        { label: "Confidence", value: "100% Deterministic" },
        { label: "False Alarm Rate", value: "0.00%" },
      ],
      actionLabel: "Inspect Canary Grid",
      onAction: onOpenCanary,
    },
    {
      id: "simulator",
      category: "simulation",
      title: "48+ MITRE Enclave Attack Matrix",
      subtitle: "In-Memory Breach Simulation Engine",
      badge: "TACTICAL READINESS",
      badgeColor: "border-cyan-500/40 text-cyan-300 bg-cyan-950/30",
      icon: Crosshair,
      iconColor: "text-cyan-400 bg-cyan-950/40 border-cyan-500/30",
      description:
        "Simulates sophisticated nation-state attack campaigns entirely offline—such as LockBit 3.0 ransomware shadow-copy deletion, memory-based Kerberoasting and SMB lateral pivots, and Stuxnet-style Modbus SCADA turbine frequency tampering—stress-testing enclave defense without live harm.",
      metrics: [
        { label: "ATT&CK Matrix", value: "48+ Built-in Techniques" },
        { label: "Threat Scenarios", value: "Ransomware, SCADA, APT" },
        { label: "Telemetry Yield", value: "High-Fidelity Event Stream" },
      ],
      actionLabel: "Launch Attack Simulation",
      onAction: onOpenSimulator,
    },
    {
      id: "roi",
      category: "economics",
      title: "Commercial Value & Insurance ROI",
      subtitle: "Total Cost of Ownership vs Cloud SIEM",
      badge: "SOVEREIGN APPLIANCE MODEL",
      badgeColor: "border-amber-500/40 text-amber-300 bg-amber-950/30",
      icon: Calculator,
      iconColor: "text-amber-400 bg-amber-950/40 border-amber-500/30",
      description:
        "Replaces unpredictable, usage-based cloud SIEM ingestion billing ($150/GB/day + egress penalties) with a fixed sovereign appliance license. Satisfies defense statutory compliance (ISO 27001, CMMC Level 3, NIST 800-171) and unlocks up to 30% discounts on cyber insurance premiums.",
      metrics: [
        { label: "Typical Annual Savings", value: "65% - 82%" },
        { label: "Licensing Model", value: "Fixed Enclave Appliance" },
        { label: "Compliance Mandate", value: "Zero Cloud Audit Certified" },
      ],
      actionLabel: "Calculate Enclave Savings",
      onAction: onOpenRoi,
    },
  ];

  const filteredTech =
    activeTab === "all" ? technologies : technologies.filter((t) => t.category === activeTab);

  return (
    <section id="enclave-tech" className="relative py-20 lg:py-28 border-b border-slate-800/80 bg-[#040813] overflow-hidden">
      {/* Background cyber accent glow */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden opacity-20">
        <div className="absolute top-1/4 -left-48 size-96 rounded-full bg-cyan-500/30 blur-3xl" />
        <div className="absolute bottom-1/4 -right-48 size-96 rounded-full bg-purple-500/20 blur-3xl" />
      </div>

      <div className="relative mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <ScrollReveal direction="up" threshold={0.1}>
          <div className="text-center max-w-3xl mx-auto">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/40 bg-cyan-950/30 px-3.5 py-1 text-[11px] font-mono font-semibold text-cyan-300">
              <span className="size-1.5 rounded-full bg-cyan-400 animate-pulse" />
              BREAKTHROUGH ENCLAVE DEFENSE STACK
            </div>
            <h2 className="mt-4 text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
              Autonomous Capabilities Built for Air-Gapped Dominance
            </h2>
            <p className="mt-4 text-sm sm:text-base leading-relaxed text-slate-400">
              ASEIOS-SOC goes beyond passive log indexing. Explore our operational defense
              modules—from hardware-level optical data diodes to autonomous micro-containment
              killswitches and zero-false-positive deception canary grids.
            </p>

            {/* Category Filter Pills */}
            <div className="mt-7 flex flex-wrap justify-center gap-2">
              {[
                { id: "all", label: "All Enclave Modules (5)" },
                { id: "defense", label: "Autonomous Defense & Hardware" },
                { id: "simulation", label: "48+ Threat Simulation" },
                { id: "economics", label: "TCO & Insurance Economics" },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`px-3.5 py-1.5 rounded-full text-xs font-mono font-semibold transition-all cursor-pointer ${
                    activeTab === tab.id
                      ? "bg-cyan-500/20 text-cyan-300 border border-cyan-400/60 shadow-xs"
                      : "bg-slate-900/60 text-slate-400 border border-slate-800 hover:border-slate-700 hover:text-slate-200"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>
        </ScrollReveal>

        {/* Feature Cards Grid */}
        <div className="mt-14 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {filteredTech.map((item, idx) => (
            <ScrollReveal key={item.id} direction="up" delay={idx * 100} threshold={0.1}>
              <div className="group h-full flex flex-col justify-between rounded-xl border border-slate-800/90 bg-[#080d1a] p-6 transition-all duration-300 hover:border-cyan-500/50 hover:bg-[#0a1124] hover:shadow-2xl hover:shadow-cyan-950/30 hover:-translate-y-1">
                <div>
                  {/* Card Top: Icon & Badge */}
                  <div className="flex items-start justify-between gap-3">
                    <div
                      className={`grid size-11 place-items-center rounded-lg border ${item.iconColor} shadow-xs transition-transform duration-300 group-hover:scale-110`}
                    >
                      <item.icon className="size-5" />
                    </div>
                    <span
                      className={`rounded-md border px-2 py-0.5 font-mono text-[9px] font-bold uppercase tracking-wider ${item.badgeColor}`}
                    >
                      {item.badge}
                    </span>
                  </div>

                  {/* Card Titles */}
                  <h3 className="mt-4 text-base font-bold text-white group-hover:text-cyan-300 transition-colors">
                    {item.title}
                  </h3>
                  <div className="font-mono text-[11px] text-slate-400 mt-0.5">{item.subtitle}</div>

                  {/* Card Description */}
                  <p className="mt-3 text-xs leading-relaxed text-slate-300">{item.description}</p>

                  {/* Key Metrics / Specs */}
                  <div className="mt-5 space-y-1.5 rounded-lg border border-slate-800/80 bg-slate-950/60 p-3.5 font-mono text-[11px]">
                    {item.metrics.map((m, mIdx) => (
                      <div key={mIdx} className="flex items-center justify-between">
                        <span className="text-slate-500">{m.label}:</span>
                        <span className="font-semibold text-slate-200">{m.value}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Action Button */}
                <div className="mt-6 pt-4 border-t border-slate-800/80">
                  <button
                    onClick={item.onAction}
                    className="w-full flex items-center justify-center gap-2 rounded-lg border border-cyan-500/40 bg-cyan-950/30 py-2.5 px-3 text-xs font-mono font-semibold text-cyan-300 transition-all hover:border-cyan-400 hover:bg-cyan-900/40 hover:text-white cursor-pointer shadow-xs"
                  >
                    <span>{item.actionLabel}</span>
                    <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-1" />
                  </button>
                </div>
              </div>
            </ScrollReveal>
          ))}
        </div>

        {/* Bottom Fast Action Banner */}
        <ScrollReveal direction="up" delay={150} threshold={0.1} className="mt-14">
          <div className="rounded-2xl border border-cyan-500/30 bg-gradient-to-r from-cyan-950/40 via-slate-900 to-indigo-950/40 p-6 sm:p-8 flex flex-wrap items-center justify-between gap-4 shadow-xl">
            <div className="flex items-center gap-4">
              <div className="grid size-12 place-items-center rounded-xl border border-cyan-500/40 bg-cyan-900/30 text-cyan-400 shrink-0">
                <Terminal className="size-6" />
              </div>
              <div>
                <div className="text-sm sm:text-base font-bold text-white font-mono flex items-center gap-2">
                  <span>READY FOR CLASSIFIED DEPLOYMENT // ENCLAVE v2026.Q4</span>
                </div>
                <p className="text-xs sm:text-sm text-slate-400 font-sans mt-0.5 max-w-xl">
                  Full threat detection, correlation, local AI investigation, and containment ready to
                  run directly in the analyst workspace.
                </p>
              </div>
            </div>

            <Link
              to="/console"
              className="flex items-center gap-2 rounded-lg bg-cyan-600 px-5 py-2.5 text-xs font-mono font-bold text-white shadow-lg shadow-cyan-950/50 hover:bg-cyan-500 transition-all hover:scale-[1.02] active:scale-[0.98] shrink-0"
            >
              <span>Open SOC Console</span>
              <ArrowRight className="size-3.5" />
            </Link>
          </div>
        </ScrollReveal>
      </div>
    </section>
  );
}
