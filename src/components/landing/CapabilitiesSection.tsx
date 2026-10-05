import {
  ShieldAlert,
  GitBranch,
  History,
  Target,
  Grid,
  Bot,
  CheckCircle2,
  ArrowRight,
} from "lucide-react";
import { Link } from "@tanstack/react-router";

export function CapabilitiesSection() {
  const capabilities = [
    {
      icon: ShieldAlert,
      title: "Threat Detection Engine",
      subtitle: "11 Modular Detection Rules",
      desc: "Deterministic rule set designed to detect the highest-impact air-gap intrusion behaviors including USB mass storage execution, encoded PowerShell, privilege escalation, and anti-forensics.",
      features: [
        "SYN-R-001: Unauthorized Removable Media Mounting",
        "SYN-R-002: Base64 Encoded PowerShell Execution",
        "SYN-R-004: SeDebugPrivilege / SeTakeOwnership Escalation",
        "SYN-R-005: Security Audit Log Clearing (Event 1102)",
      ],
      tag: "Rule-Based",
      color: "text-rose-400 border-rose-500/30 bg-rose-950/20",
    },
    {
      icon: GitBranch,
      title: "Event Correlation",
      subtitle: "Cross-Host Clustering",
      desc: "Connects discrete events across distinct operating systems (Windows, Linux, firewall, database) into unified incident chains based on identity sessions, host proximity, and temporal sliding windows.",
      features: [
        "Configurable 30-minute sliding window clustering",
        "Unified host and user entity resolution",
        "Boundary egress denial cross-referencing",
        "Separation of distinct intrusion campaigns",
      ],
      tag: "Temporal Clustering",
      color: "text-cyan-400 border-cyan-500/30 bg-cyan-950/20",
    },
    {
      icon: History,
      title: "Attack Reconstruction",
      subtitle: "Chronological Causal Timeline",
      desc: "Reconstructs the full sequence of an intrusion from the initial physical USB mount down to defense evasion attempts, highlighting exact timestamps, parent processes, and user accounts.",
      features: [
        "Visual timeline nodes with supporting evidence snippets",
        "Severity escalation tracking and confidence scores",
        "Direct link between raw log lines and high-level findings",
        "Multi-stage kill chain progression modeling",
      ],
      tag: "Forensic Timeline",
      color: "text-amber-400 border-amber-500/30 bg-amber-950/20",
    },
    {
      icon: Target,
      title: "IOC Analysis",
      subtitle: "Artifact & Indicator Extraction",
      desc: "Automatically identifies and indexes suspicious indicators of compromise from raw telemetry, categorizing them for rapid containment across isolated endpoints.",
      features: [
        "Suspicious executables and staging directory paths",
        "Target internal IPs and boundary deny destinations",
        "Compressed staging archives and exfiltration artifacts",
        "Exportable artifact catalog for fleet-wide hunting",
      ],
      tag: "Artifact Extraction",
      color: "text-emerald-400 border-emerald-500/30 bg-emerald-950/20",
    },
    {
      icon: Grid,
      title: "MITRE ATT&CK Mapping",
      subtitle: "Standardized Tactic Attribution",
      desc: "Tags all correlated threats and individual events with standard MITRE ATT&CK tactics and techniques, allowing analysts to immediately understand attacker objectives.",
      features: [
        "Initial Access: TA0001 (Replication Through Removable Media)",
        "Execution: TA0002 (Command & Scripting Interpreter)",
        "Privilege Escalation: TA0004 (Abuse Elevation Control)",
        "Defense Evasion: TA0005 (Indicator Removal on Host)",
      ],
      tag: "ATT&CK Framework",
      color: "text-indigo-400 border-indigo-500/30 bg-indigo-950/20",
    },
    {
      icon: Bot,
      title: "Offline AI Investigation",
      subtitle: "Local LLM Narrative & Assistant",
      desc: "Generates executive summaries, root cause assessments, and recommended actions using local Ollama models (Mistral / Llama 3.2) or deterministic template fallbacks with zero hallucination verification.",
      features: [
        "Strict anti-hallucination verification against ground truth",
        "Conversational analyst assistant grounded in parsed logs",
        "Zero-cloud template engine for mathematically defensible results",
        "Automated actionable containment playbooks",
      ],
      tag: "Local LLM // Zero Cloud",
      color: "text-purple-400 border-purple-500/30 bg-purple-950/20",
    },
  ];

  return (
    <section id="capabilities" className="py-16 lg:py-24 border-b border-slate-800/60 bg-[#070b14]">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-1.5 rounded-full border border-indigo-500/30 bg-indigo-950/20 px-3 py-1 text-[11px] font-mono font-semibold text-indigo-300">
            AIR-GAP CAPABILITIES
          </div>
          <h2 className="mt-3 text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
            Engineered for High-Security Environments
          </h2>
          <p className="mt-4 text-sm sm:text-base leading-relaxed text-slate-400">
            ASEIOS-SOC combines deterministic threat analytics with local generative AI to convert
            millions of raw air-gap events into clear, forensic-grade incident investigations.
          </p>
        </div>

        {/* 6 Capabilities Cards Grid */}
        <div className="mt-12 grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {capabilities.map((c, i) => (
            <div
              key={i}
              className="flex flex-col justify-between rounded-xl border border-slate-800 bg-[#090e1a] p-6 hover:border-slate-700 transition-all hover:-translate-y-0.5 shadow-sm"
            >
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div className={`grid size-10 place-items-center rounded-lg border ${c.color}`}>
                    <c.icon className="size-5" />
                  </div>
                  <span className="font-mono text-[10px] uppercase font-bold text-slate-500 border border-slate-800 bg-slate-900/80 px-2 py-0.5 rounded">
                    {c.tag}
                  </span>
                </div>

                <h3 className="text-base font-extrabold text-white">{c.title}</h3>
                <div className="text-xs font-mono font-bold text-cyan-400 mt-0.5">{c.subtitle}</div>
                <p className="mt-2.5 text-xs text-slate-400 leading-relaxed">{c.desc}</p>

                <div className="mt-4 space-y-1.5 border-t border-slate-800/80 pt-3">
                  {c.features.map((feat, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-xs text-slate-300">
                      <CheckCircle2 className="size-3.5 text-emerald-400 shrink-0 mt-0.5" />
                      <span className="leading-snug text-[11px]">{feat}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="mt-6 pt-3 border-t border-slate-800/60">
                <Link
                  to="/console"
                  className="inline-flex items-center gap-1.5 text-xs font-mono font-semibold text-cyan-400 hover:text-cyan-300 transition-colors"
                >
                  <span>Test in console</span>
                  <ArrowRight className="size-3" />
                </Link>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
