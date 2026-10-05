import { useState } from "react";
import {
  Server,
  Cpu,
  Shield,
  Database,
  Terminal,
  Bot,
  Lock,
  CloudOff,
  X,
  CheckCircle2,
  ArrowDown,
} from "lucide-react";

interface ArchNode {
  id: string;
  step: string;
  icon: typeof Server;
  name: string;
  subtitle: string;
  status: string;
  statusType: "input" | "processing" | "detection" | "persistent" | "offline" | "active";
  summary: string;
  techStack: string;
  enclaveRole: string;
  sovereigntyGuarantee: string;
  sources?: string[];
  capabilities?: string[];
}

const ARCH_NODES: ArchNode[] = [
  {
    id: "sources",
    step: "01",
    icon: Server,
    name: "SECURITY SOURCES",
    subtitle: "Windows / Sysmon / Linux / FW / DB",
    status: "LOCAL INPUT",
    statusType: "input",
    summary:
      "Raw event logs from endpoints, identity servers, firewalls, and audit services ingested via local file transfer or syslog without cloud forwarders.",
    techStack: "Windows Security Events · Sysmon XML · Linux auth.log · Appliance Syslog",
    enclaveRole:
      "Origin of security telemetry inside the isolated perimeter. Data is ingested from local network segments, physical optical drives, or secure SFTP staging drops.",
    sovereigntyGuarantee: "Inbound only · Zero telemetry or metadata dispatched outward.",
    sources: ["Windows", "Sysmon", "Linux", "Firewalls", "DB"],
  },
  {
    id: "engine",
    step: "02",
    icon: Cpu,
    name: "ASEIOS-SOC ENGINE",
    subtitle: "Spring Boot · Java 21",
    status: "PROCESSING",
    statusType: "processing",
    summary:
      "Raw security events are parsed and normalized into a common internal representation before deterministic detection and correlation.",
    techStack: "Java 21 · Spring Boot 3.5 · ParserFactory · LogNormalizer",
    enclaveRole:
      "Core server daemon running natively in the enclave JVM. Validates schema structures, maps event IDs to standard ontology, and enforces chronological integrity.",
    sovereigntyGuarantee: "100% in-process execution · Zero external RPC or CDN dependencies.",
    capabilities: ["Ingestion", "Normalization", "Validation", "Sequencing"],
  },
  {
    id: "threat",
    step: "03",
    icon: Shield,
    name: "THREAT ANALYSIS",
    subtitle: "Rules · IOC · MITRE ATT&CK",
    status: "DETECTION",
    statusType: "detection",
    summary:
      "Detection rules, event correlation, IOC extraction and MITRE ATT&CK mapping transform raw events into structured security evidence.",
    techStack: "11 Deterministic Rules · Temporal Sliding Windows · MITRE ATT&CK Matrix",
    enclaveRole:
      "Deterministic security engine operates first. Identifies suspicious executions, credential dumping, lateral movement, and privilege abuse with zero external intelligence calls.",
    sovereigntyGuarantee: "Deterministic logic · Same evidence produces identical verdicts.",
    capabilities: ["11 Deterministic Rules", "Temporal Correlation", "IOC Extraction", "MITRE Mapping"],
  },
  {
    id: "evidence",
    step: "04",
    icon: Database,
    name: "LOCAL EVIDENCE",
    subtitle: "PostgreSQL 16",
    status: "PERSISTENT",
    statusType: "persistent",
    summary:
      "Enclave PostgreSQL 16 stores normalized events, incidents, recommendations, and immutable audit logs on local persistent disks.",
    techStack: "PostgreSQL 16 · Spring Data JPA · Flyway Migrations",
    enclaveRole:
      "Enclave persistence store housing raw event archives, correlation graphs, investigator notes, and append-only tamper-evident audit records.",
    sovereigntyGuarantee: "On-premise storage · Never synced to remote databases or external backups.",
    capabilities: ["Normalized Events", "Incident Records", "Analyst Notes", "Append-Only Audit"],
  },
  {
    id: "ai",
    step: "05",
    icon: Bot,
    name: "LOCAL AI / OLLAMA",
    subtitle: "Ollama / deterministic fallback",
    status: "OFFLINE",
    statusType: "offline",
    summary:
      "Optional locally hosted Ollama models help analysts interpret investigation evidence without sending security data to external services.",
    techStack: "Ollama (Localhost:11434) · Deterministic Template Fallback",
    enclaveRole:
      "Evidence-grounded local LLM assistance. Cross-references confirmed telemetry to explain attack paths and draft investigative steps, falling back cleanly to deterministic templates if offline.",
    sovereigntyGuarantee: "Zero cloud API keys · Telemetry never leaves the host environment.",
    capabilities: ["Evidence Grounding", "Incident Synthesis", "Triaging Guidance", "Template Fallback"],
  },
  {
    id: "console",
    step: "06",
    icon: Terminal,
    name: "ANALYST CONSOLE",
    subtitle: "React · TanStack",
    status: "ACTIVE",
    statusType: "active",
    summary:
      "Air-gapped React analyst workstation provides interactive timeline analysis, graph reconstruction, AI-assisted chat, and exportable forensic reports.",
    techStack: "React 19 · TanStack Router/Query · Tailwind CSS · Lucide Icons",
    enclaveRole:
      "Air-gapped web client served directly from the enclave host. Renders live log telemetry, attack timelines, evidence relationship graphs, and courtroom-defensible reports.",
    sovereigntyGuarantee: "Zero telemetry tracking · No external CDN scripts or remote fonts.",
    capabilities: ["Attack Timeline", "Evidence Graph", "AI Investigation", "Forensic Reports"],
  },
];

function getStatusBadge(type: ArchNode["statusType"], text: string) {
  switch (type) {
    case "input":
      return (
        <span className="inline-flex items-center gap-1 rounded bg-emerald-950/80 px-1.5 py-0.5 font-mono text-[9px] font-bold text-emerald-400 border border-emerald-500/30">
          <span className="size-1.5 rounded-full bg-emerald-400 animate-pulse" />
          {text}
        </span>
      );
    case "processing":
      return (
        <span className="inline-flex items-center gap-1 rounded bg-cyan-950/80 px-1.5 py-0.5 font-mono text-[9px] font-bold text-cyan-400 border border-cyan-500/30">
          <span className="size-1.5 rounded-full bg-cyan-400 animate-pulse" />
          {text}
        </span>
      );
    case "detection":
      return (
        <span className="inline-flex items-center gap-1 rounded bg-amber-950/80 px-1.5 py-0.5 font-mono text-[9px] font-bold text-amber-400 border border-amber-500/30">
          <span className="size-1.5 rounded-full bg-amber-400" />
          {text}
        </span>
      );
    case "persistent":
      return (
        <span className="inline-flex items-center gap-1 rounded bg-blue-950/80 px-1.5 py-0.5 font-mono text-[9px] font-bold text-blue-400 border border-blue-500/30">
          <span className="size-1.5 rounded-full bg-blue-400" />
          {text}
        </span>
      );
    case "offline":
      return (
        <span className="inline-flex items-center gap-1 rounded bg-purple-950/80 px-1.5 py-0.5 font-mono text-[9px] font-bold text-purple-300 border border-purple-500/30">
          <span className="size-1.5 rounded-full bg-purple-400" />
          {text}
        </span>
      );
    case "active":
      return (
        <span className="inline-flex items-center gap-1 rounded bg-emerald-950/80 px-1.5 py-0.5 font-mono text-[9px] font-bold text-emerald-400 border border-emerald-500/30">
          <span className="size-1.5 rounded-full bg-emerald-400" />
          {text}
        </span>
      );
  }
}

function NodeCard({
  node,
  isActive,
  onSelect,
  className = "",
  activeBorderClass = "border-cyan-400 bg-cyan-950/30 shadow-[0_0_20px_rgba(6,182,212,0.2)] ring-1 ring-cyan-500/30",
  focusRingClass = "focus-visible:ring-cyan-400",
  iconClass = "text-cyan-400",
}: {
  node: ArchNode;
  isActive: boolean;
  onSelect: () => void;
  className?: string;
  activeBorderClass?: string;
  focusRingClass?: string;
  iconClass?: string;
}) {
  const Icon = node.icon;
  return (
    <div
      role="button"
      tabIndex={0}
      aria-label={`Inspect ${node.name} architecture stage`}
      aria-pressed={isActive}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          onSelect();
        }
      }}
      className={`rounded-xl border p-4 sm:p-5 transition-all cursor-pointer text-left focus:outline-none focus-visible:ring-2 ${focusRingClass} ${className} ${
        isActive
          ? activeBorderClass
          : "border-slate-800 bg-[#090f1e] hover:border-slate-700 hover:bg-[#0c1426]"
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
        <div className="flex items-center gap-2.5">
          <span className="font-mono text-[10px] font-bold text-cyan-400 bg-cyan-950/80 border border-cyan-500/30 px-1.5 py-0.5 rounded">
            NODE {node.step}
          </span>
          <Icon className={`size-4 ${iconClass}`} />
          <span className="font-mono text-xs sm:text-sm font-bold text-white tracking-wide">
            {node.name}
          </span>
        </div>
        {getStatusBadge(node.statusType, node.status)}
      </div>

      <div className="text-[11px] font-mono text-slate-400 mb-2">
        {node.subtitle}
      </div>

      {node.sources && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-1.5 pt-2 border-t border-slate-800/80">
          {node.sources.map((src) => (
            <div
              key={src}
              className="rounded bg-[#050914] border border-slate-800 px-2 py-1 text-center font-mono text-[10px] text-slate-300 font-medium"
            >
              {src}
            </div>
          ))}
        </div>
      )}

      {node.summary && !node.sources && (
        <p className="text-xs text-slate-400 leading-relaxed mb-3">
          {node.summary}
        </p>
      )}

      {node.capabilities && (
        <div className="flex flex-wrap gap-1.5 pt-2 border-t border-slate-800/80">
          {node.capabilities.map((cap) => (
            <span
              key={cap}
              className="rounded bg-[#050914] border border-slate-800 px-2 py-0.5 font-mono text-[10px] text-slate-300"
            >
              {cap}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export function ArchitectureSection() {
  const [activeNodeId, setActiveNodeId] = useState<string>("engine");

  const activeNode =
    ARCH_NODES.find((n) => n.id === activeNodeId) || ARCH_NODES[1];

  const nodeSources = ARCH_NODES[0];
  const nodeEngine = ARCH_NODES[1];
  const nodeThreat = ARCH_NODES[2];
  const nodeEvidence = ARCH_NODES[3];
  const nodeAi = ARCH_NODES[4];
  const nodeConsole = ARCH_NODES[5];

  return (
    <section
      id="architecture"
      className="py-16 lg:py-24 border-b border-slate-800/60 bg-[#070b14] relative overflow-hidden"
    >
      {/* Component-scoped CSS for subtle data flow animations and reduced-motion compliance */}
      <style>{`
        @keyframes flowDashForward {
          from {
            stroke-dashoffset: 24;
          }
          to {
            stroke-dashoffset: 0;
          }
        }
        @keyframes flowPulseTravel {
          0% {
            opacity: 0.15;
            transform: translateY(-4px);
          }
          50% {
            opacity: 0.9;
          }
          100% {
            opacity: 0.15;
            transform: translateY(16px);
          }
        }
        .anim-flow-dash {
          stroke-dasharray: 4 6;
          animation: flowDashForward 1.6s linear infinite;
        }
        .anim-flow-dash-fast {
          stroke-dasharray: 4 4;
          animation: flowDashForward 1.2s linear infinite;
        }
        .anim-pulse-marker {
          animation: flowPulseTravel 2.4s ease-in-out infinite;
        }
        @media (prefers-reduced-motion: reduce) {
          .anim-flow-dash,
          .anim-flow-dash-fast {
            animation: none !important;
            stroke-dasharray: none !important;
          }
          .anim-pulse-marker {
            animation: none !important;
          }
        }
      `}</style>

      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 relative z-10">
        {/* Section Heading & Subtitle */}
        <div className="text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/30 bg-cyan-950/30 px-3.5 py-1 text-[11px] font-mono font-semibold text-cyan-300 tracking-wide">
            <span className="size-1.5 rounded-full bg-cyan-400 animate-pulse" />
            AIR-GAPPED ARCHITECTURE // NO CLOUD DEPENDENCY
          </div>
          <h2 className="mt-3 text-3xl font-extrabold tracking-tight text-white sm:text-4xl font-mono uppercase">
            ARCHITECTURE // INSIDE THE ENCLAVE
          </h2>
          <p className="mt-4 text-sm sm:text-base leading-relaxed text-slate-300">
            Every stage of investigation runs locally inside the isolated environment.
            Security evidence, detection results, investigation context, and AI analysis
            remain within the enclave.
          </p>
        </div>

        {/* Visual Egress Disconnect (Internet / Cloud Outside the Enclave) */}
        <div className="mt-12 max-w-2xl mx-auto flex flex-col items-center">
          <div className="w-full flex items-center justify-between gap-3 px-4 py-2.5 rounded-lg border border-slate-800/80 bg-[#0b101c]/90 text-slate-400">
            <div className="flex items-center gap-2">
              <CloudOff className="size-4 text-slate-500" />
              <span className="font-mono text-xs text-slate-400 font-semibold tracking-wider uppercase">
                INTERNET / CLOUD
              </span>
            </div>
            <div className="flex items-center gap-2 font-mono text-[11px] text-red-400 bg-red-950/40 px-2 py-0.5 rounded border border-red-500/30">
              <X className="size-3.5 text-red-400" />
              <span className="font-bold tracking-wider">EGRESS BLOCKED</span>
            </div>
            <span className="hidden sm:inline font-mono text-[10px] text-slate-500">
              NO APPLICATION-LEVEL CLOUD DEPENDENCIES
            </span>
          </div>

          {/* Blocked connector drop line */}
          <div className="flex flex-col items-center my-1 select-none">
            <div className="w-px h-3 bg-red-500/40" />
            <div className="grid size-5 place-items-center rounded-full bg-[#0a0f1d] border border-red-500/60 text-red-400 text-[10px] font-mono font-bold shadow-sm">
              ✕
            </div>
            <div className="w-px h-3 bg-red-500/40" />
          </div>

          <span className="font-mono text-[10px] tracking-wider uppercase text-slate-400 font-semibold mb-1">
            DESIGNED FOR AIR-GAPPED DEPLOYMENT
          </span>
        </div>

        {/* Main Central Architecture Visualization Container: AIR-GAPPED ENCLAVE */}
        <div className="rounded-2xl border-2 border-cyan-500/30 bg-[#060b16]/95 shadow-[0_0_50px_rgba(6,182,212,0.06)] relative p-4 sm:p-7 lg:p-9 backdrop-blur-md">
          {/* Enclave Header Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-cyan-500/20 pb-4 mb-7">
            <div className="flex items-center gap-3">
              <span className="grid size-8 place-items-center rounded-lg bg-cyan-950/80 border border-cyan-500/40 text-cyan-300">
                <Lock className="size-4" />
              </span>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm font-bold tracking-wider text-cyan-300 uppercase">
                    AIR-GAPPED ENCLAVE
                  </span>
                  <span className="size-2 rounded-full bg-emerald-400 animate-pulse" />
                </div>
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest block">
                  CLASSIFICATION: LOCAL PROCESSING // STANDALONE NODE
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2 font-mono text-[11px]">
              <span className="rounded bg-emerald-950/60 border border-emerald-500/30 px-2.5 py-1 text-emerald-300 font-semibold flex items-center gap-1.5">
                <CheckCircle2 className="size-3 text-emerald-400" />
                ISOLATED VOLUMES
              </span>
              <span className="hidden sm:inline rounded bg-slate-900 border border-slate-800 px-2.5 py-1 text-slate-400">
                OFFLINE INTELLIGENCE
              </span>
            </div>
          </div>

          {/* ========================================================
              DIAGRAM FLOW GRAPH (DESKTOP & RESPONSIVE VIEW)
             ======================================================== */}
          <div className="flex flex-col items-center">
            {/* LEVEL 1: NODE 01 - SECURITY SOURCES */}
            <div className="w-full max-w-3xl">
              <NodeCard
                node={nodeSources}
                isActive={activeNodeId === "sources"}
                onSelect={() => setActiveNodeId("sources")}
                iconClass="text-emerald-400"
                activeBorderClass="border-emerald-400 bg-emerald-950/30 shadow-[0_0_20px_rgba(52,211,153,0.2)] ring-1 ring-emerald-500/30"
                focusRingClass="focus-visible:ring-emerald-400"
              />
            </div>

            {/* FLOW CONNECTOR 1: SOURCES -> ENGINE */}
            <div className="flex flex-col items-center my-1 sm:my-2 w-full max-w-3xl">
              <svg className="w-full h-8 sm:h-10 overflow-visible" viewBox="0 0 400 36">
                <line
                  x1="200"
                  y1="0"
                  x2="200"
                  y2="36"
                  stroke="#0891b2"
                  strokeWidth="2"
                  className="anim-flow-dash"
                />
                <circle cx="200" cy="18" r="3" fill="#22d3ee" className="anim-pulse-marker" />
              </svg>
              <span className="font-mono text-[9px] text-cyan-400 tracking-wider bg-[#060b16] px-2 py-0.5 rounded border border-cyan-500/20 -mt-2 z-10">
                RAW SECURITY LOGS (UNIDIRECTIONAL INGESTION)
              </span>
            </div>

            {/* LEVEL 2: NODE 02 - ASEIOS-SOC PROCESSING ENGINE */}
            <div className="w-full max-w-xl">
              <NodeCard
                node={nodeEngine}
                isActive={activeNodeId === "engine"}
                onSelect={() => setActiveNodeId("engine")}
                iconClass="text-cyan-400"
                activeBorderClass="border-cyan-400 bg-cyan-950/30 shadow-[0_0_20px_rgba(6,182,212,0.2)] ring-1 ring-cyan-500/30"
                focusRingClass="focus-visible:ring-cyan-400"
              />
            </div>

            {/* FLOW CONNECTOR 2: ENGINE -> SPLIT (LOCAL EVIDENCE & THREAT ANALYSIS) */}
            <div className="hidden sm:block w-full max-w-3xl my-2">
              <svg className="w-full h-12 overflow-visible" viewBox="0 0 600 48">
                {/* Trunk */}
                <line
                  x1="300"
                  y1="0"
                  x2="300"
                  y2="16"
                  stroke="#0891b2"
                  strokeWidth="2"
                  className="anim-flow-dash"
                />
                {/* Horizontal branch line */}
                <path
                  d="M150 48 L150 24 L450 24 L450 48"
                  fill="none"
                  stroke="#0891b2"
                  strokeWidth="2"
                  className="anim-flow-dash"
                />
                <circle cx="150" cy="36" r="3" fill="#38bdf8" className="anim-pulse-marker" />
                <circle cx="450" cy="36" r="3" fill="#fbbf24" className="anim-pulse-marker" />
              </svg>
            </div>

            {/* Mobile Vertical Indicator (sm:hidden) */}
            <div className="sm:hidden flex flex-col items-center my-2">
              <ArrowDown className="size-4 text-cyan-400 animate-bounce" />
              <span className="font-mono text-[9px] text-cyan-400 tracking-wider">
                NORMALIZED EVENT STREAM
              </span>
            </div>

            {/* LEVEL 3: PARALLEL SPLIT - LOCAL EVIDENCE (04) & THREAT ANALYSIS (03) */}
            <div className="w-full max-w-4xl grid gap-4 sm:grid-cols-2">
              {/* NODE 04: LOCAL EVIDENCE (PostgreSQL 16) */}
              <NodeCard
                node={nodeEvidence}
                isActive={activeNodeId === "evidence"}
                onSelect={() => setActiveNodeId("evidence")}
                iconClass="text-blue-400"
                activeBorderClass="border-blue-400 bg-blue-950/30 shadow-[0_0_20px_rgba(59,130,246,0.2)] ring-1 ring-blue-500/30"
                focusRingClass="focus-visible:ring-blue-400"
              />

              {/* NODE 03: THREAT ANALYSIS (Rules · IOC · MITRE ATT&CK) */}
              <NodeCard
                node={nodeThreat}
                isActive={activeNodeId === "threat"}
                onSelect={() => setActiveNodeId("threat")}
                iconClass="text-amber-400"
                activeBorderClass="border-amber-400 bg-amber-950/30 shadow-[0_0_20px_rgba(245,158,11,0.2)] ring-1 ring-amber-500/30"
                focusRingClass="focus-visible:ring-amber-400"
              />
            </div>

            {/* FLOW CONNECTOR 3: CONVERGE INTO LOCAL AI */}
            <div className="hidden sm:block w-full max-w-3xl my-2">
              <svg className="w-full h-12 overflow-visible" viewBox="0 0 600 48">
                {/* Converging lines */}
                <path
                  d="M150 0 L150 24 L300 24 L300 48"
                  fill="none"
                  stroke="#0891b2"
                  strokeWidth="2"
                  className="anim-flow-dash"
                />
                <path
                  d="M450 0 L450 24 L300 24"
                  fill="none"
                  stroke="#0891b2"
                  strokeWidth="2"
                  className="anim-flow-dash"
                />
                <circle cx="300" cy="36" r="3" fill="#c084fc" className="anim-pulse-marker" />
              </svg>
            </div>

            {/* Mobile Vertical Indicator (sm:hidden) */}
            <div className="sm:hidden flex flex-col items-center my-2">
              <ArrowDown className="size-4 text-cyan-400 animate-bounce" />
              <span className="font-mono text-[9px] text-cyan-400 tracking-wider">
                EVIDENCE CONVERGENCE
              </span>
            </div>

            {/* LEVEL 4: NODE 05 - LOCAL AI / OLLAMA */}
            <div className="w-full max-w-xl">
              <NodeCard
                node={nodeAi}
                isActive={activeNodeId === "ai"}
                onSelect={() => setActiveNodeId("ai")}
                iconClass="text-purple-300"
                activeBorderClass="border-purple-400 bg-purple-950/30 shadow-[0_0_20px_rgba(192,132,252,0.2)] ring-1 ring-purple-500/30"
                focusRingClass="focus-visible:ring-purple-400"
              />
            </div>

            {/* FLOW CONNECTOR 4: LOCAL AI -> ANALYST CONSOLE */}
            <div className="flex flex-col items-center my-1 sm:my-2 w-full max-w-3xl">
              <svg className="w-full h-8 sm:h-10 overflow-visible" viewBox="0 0 400 36">
                <line
                  x1="200"
                  y1="0"
                  x2="200"
                  y2="36"
                  stroke="#0891b2"
                  strokeWidth="2"
                  className="anim-flow-dash-fast"
                />
                <circle cx="200" cy="18" r="3" fill="#34d399" className="anim-pulse-marker" />
              </svg>
              <span className="font-mono text-[9px] text-emerald-400 tracking-wider bg-[#060b16] px-2 py-0.5 rounded border border-emerald-500/20 -mt-2 z-10">
                FORENSIC CONTEXT & AI TRIAGE SYNTHESIS
              </span>
            </div>

            {/* LEVEL 5: NODE 06 - ANALYST CONSOLE */}
            <div className="w-full max-w-xl">
              <NodeCard
                node={nodeConsole}
                isActive={activeNodeId === "console"}
                onSelect={() => setActiveNodeId("console")}
                iconClass="text-emerald-400"
                activeBorderClass="border-emerald-400 bg-emerald-950/30 shadow-[0_0_20px_rgba(52,211,153,0.2)] ring-1 ring-emerald-500/30"
                focusRingClass="focus-visible:ring-emerald-400"
              />
            </div>
          </div>

          {/* ========================================================
              ACTIVE CONTEXT INSPECTOR PANEL
             ======================================================== */}
          <div className="mt-8 rounded-xl border border-cyan-500/40 bg-[#040813] p-4 sm:p-6 relative overflow-hidden shadow-inner">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <span className="font-mono text-[10px] uppercase font-bold tracking-widest text-cyan-400 bg-cyan-950/70 px-2 py-0.5 rounded border border-cyan-500/30">
                  NODE INSPECTOR
                </span>
                <span className="text-xs font-mono text-white font-bold">
                  STAGE {activeNode.step} // {activeNode.name}
                </span>
              </div>
              <span className="text-[10px] font-mono text-slate-400">
                Hover or select any node above to inspect its isolated enclave function
              </span>
            </div>

            <div className="grid gap-4 md:grid-cols-3">
              <div className="md:col-span-2 space-y-2">
                <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
                  ENCLAVE FUNCTION
                </div>
                <p className="text-xs sm:text-sm text-slate-200 leading-relaxed">
                  {activeNode.enclaveRole}
                </p>
                <div className="pt-2 text-[11px] font-mono text-slate-400">
                  <span className="text-cyan-400 font-semibold">RUNTIME STACK: </span>
                  {activeNode.techStack}
                </div>
              </div>

              <div className="rounded-lg border border-slate-800 bg-[#070d1a] p-3 text-xs flex flex-col justify-between">
                <div>
                  <div className="flex items-center gap-1.5 text-emerald-400 font-mono text-[11px] font-bold mb-1">
                    <CheckCircle2 className="size-3.5" />
                    <span>SOVEREIGNTY STATUS</span>
                  </div>
                  <p className="text-[11px] text-slate-300 leading-relaxed">
                    {activeNode.sovereigntyGuarantee}
                  </p>
                </div>
                <div className="mt-3 pt-2 border-t border-slate-800 text-[10px] font-mono text-slate-400">
                  Egress Status: <span className="text-emerald-400">ZERO NETWORK EMISSION</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* ========================================================
            BOTTOM PROOF POINTS
            Replacing large cards with 3 compact proof points
           ======================================================== */}
        <div className="mt-10 grid gap-4 sm:grid-cols-3">
          <div className="rounded-xl border border-slate-800/80 bg-[#080d19] p-5 text-xs transition-colors hover:border-slate-700">
            <span className="font-mono text-[10px] uppercase font-bold text-cyan-400 block mb-1.5">
              01 — LOCAL PROCESSING
            </span>
            <p className="text-slate-300 leading-relaxed text-xs">
              Security logs and investigation data are processed within the deployment environment.
            </p>
          </div>

          <div className="rounded-xl border border-slate-800/80 bg-[#080d19] p-5 text-xs transition-colors hover:border-slate-700">
            <span className="font-mono text-[10px] uppercase font-bold text-cyan-400 block mb-1.5">
              02 — LOCAL AI
            </span>
            <p className="text-slate-300 leading-relaxed text-xs">
              Optional Ollama inference keeps AI-assisted investigation inside the enclave.
            </p>
          </div>

          <div className="rounded-xl border border-slate-800/80 bg-[#080d19] p-5 text-xs transition-colors hover:border-slate-700">
            <span className="font-mono text-[10px] uppercase font-bold text-cyan-400 block mb-1.5">
              03 — LOCAL EVIDENCE
            </span>
            <p className="text-slate-300 leading-relaxed text-xs">
              Cases, normalized events and investigation artifacts remain in local storage.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
