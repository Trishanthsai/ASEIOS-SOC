import { Link } from "@tanstack/react-router";
import {
  ShieldAlert,
  Terminal,
  Cpu,
  Radio,
  ArrowRight,
  Database,
  Activity,
  Layers,
  Lock,
} from "lucide-react";

export function Hero() {
  return (
    <section className="relative overflow-hidden pt-12 pb-16 lg:pt-20 lg:pb-24 border-b border-slate-800/60">
      {/* Background radial gradient and cyber grid */}
      <div
        className="pointer-events-none absolute inset-0 opacity-25"
        style={{
          backgroundImage: `
            radial-gradient(ellipse 60% 40% at 50% -20%, rgba(14, 165, 233, 0.25), transparent 70%),
            linear-gradient(to right, rgba(51, 65, 85, 0.15) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(51, 65, 85, 0.15) 1px, transparent 1px)
          `,
          backgroundSize: "auto, 32px 32px, 32px 32px",
        }}
      />

      <div className="relative mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col items-center text-center">
          {/* Top Enclave Status Pill */}
          <div className="inline-flex items-center gap-2 rounded-full border border-slate-800 bg-[#0d1424] px-3 py-1 text-xs text-slate-300 shadow-sm mb-6">
            <span className="flex size-2 rounded-full bg-emerald-400" />
            <span className="font-mono text-[11px] uppercase tracking-wider text-slate-400">
              OFFLINE-FIRST ENCLAVE SOC // ZERO EGRESS
            </span>
          </div>

          {/* Main Title */}
          <h1 className="max-w-4xl font-display text-4xl font-extrabold tracking-tight text-white sm:text-5xl lg:text-6xl">
            Offline Intelligence for{" "}
            <span className="bg-gradient-to-r from-cyan-400 via-sky-300 to-indigo-400 bg-clip-text text-transparent">
              Air-Gapped Security
            </span>{" "}
            Operations
          </h1>

          {/* Subtitle / Value Proposition */}
          <p className="mt-5 max-w-2xl text-sm sm:text-base leading-relaxed text-slate-400">
            <strong>ASEIOS-SOC</strong> ingests, normalizes, and reconstructs security telemetry
            within isolated networks. Perform rule-based threat detection, cross-host event
            correlation, attack timeline reconstruction, IOC analysis, MITRE ATT&CK mapping, and
            local AI investigation—without transmitting a single byte outside the enclave boundary.
          </p>

          {/* Visual Indicator Badges */}
          <div className="mt-7 flex flex-wrap justify-center gap-2 sm:gap-3">
            <span className="inline-flex items-center gap-1.5 rounded-md border border-cyan-500/30 bg-cyan-950/20 px-3 py-1 text-xs font-mono font-semibold text-cyan-300">
              <Lock className="size-3 text-cyan-400" />
              AIR-GAPPED
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-md border border-indigo-500/30 bg-indigo-950/20 px-3 py-1 text-xs font-mono font-semibold text-indigo-300">
              <Cpu className="size-3 text-indigo-400" />
              LOCAL AI (OLLAMA / TEMPLATE)
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/30 bg-emerald-950/20 px-3 py-1 text-xs font-mono font-semibold text-emerald-300">
              <Radio className="size-3 text-emerald-400" />
              ZERO CLOUD DEPENDENCY
            </span>
          </div>

          {/* CTAs */}
          <div className="mt-8 flex flex-wrap items-center justify-center gap-4">
            <Link
              to="/console"
              className="inline-flex items-center gap-2 rounded-md bg-cyan-600 px-6 py-3 text-sm font-bold text-white shadow-lg shadow-cyan-950/50 hover:bg-cyan-500 transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              <Terminal className="size-4" />
              <span>Launch SOC Console</span>
              <ArrowRight className="size-4" />
            </Link>

            <a
              href="#why"
              className="inline-flex items-center gap-2 rounded-md border border-slate-700 bg-slate-850 px-5 py-3 text-sm font-semibold text-slate-300 hover:border-slate-600 hover:bg-slate-800 hover:text-white transition-all"
            >
              <span>Explore Platform</span>
            </a>
          </div>

          {/* Live Enclave Telemetry Card Preview */}
          <div className="mt-12 w-full max-w-4xl rounded-xl border border-slate-800 bg-[#090e1a] p-4 text-left shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
              <div className="flex items-center gap-2">
                <span className="size-3 rounded-full bg-red-500/60 inline-block" />
                <span className="size-3 rounded-full bg-yellow-500/60 inline-block" />
                <span className="size-3 rounded-full bg-green-500/60 inline-block" />
                <span className="ml-2 font-mono text-[11px] text-slate-400">
                  enclave-terminal // DRDO-NPCIL-SECURE-ENCLAVE
                </span>
              </div>
              <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-slate-300 border border-slate-700">
                STATUS: AIR-GAP LOCKED
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="rounded border border-slate-800/80 bg-slate-950/60 p-2.5">
                <div className="text-[10px] uppercase text-slate-500 font-bold">
                  Boundary Egress
                </div>
                <div className="mt-1 font-bold text-red-400 flex items-center gap-1.5">
                  <span className="size-1.5 rounded-full bg-red-400 animate-pulse" />
                  BLOCKED (0 B/s)
                </div>
              </div>

              <div className="rounded border border-slate-800/80 bg-slate-950/60 p-2.5">
                <div className="text-[10px] uppercase text-slate-500 font-bold">
                  Detection Rules
                </div>
                <div className="mt-1 font-bold text-cyan-400 flex items-center gap-1.5">
                  <Activity className="size-3.5 text-cyan-400" />
                  11 MITRE Rules Active
                </div>
              </div>

              <div className="rounded border border-slate-800/80 bg-slate-950/60 p-2.5">
                <div className="text-[10px] uppercase text-slate-500 font-bold">
                  AI Narrative Engine
                </div>
                <div className="mt-1 font-bold text-indigo-300 flex items-center gap-1.5">
                  <Cpu className="size-3.5 text-indigo-400" />
                  Ollama / Deterministic
                </div>
              </div>

              <div className="rounded border border-slate-800/80 bg-slate-950/60 p-2.5">
                <div className="text-[10px] uppercase text-slate-500 font-bold">Report Format</div>
                <div className="mt-1 font-bold text-emerald-400 flex items-center gap-1.5">
                  <ShieldAlert className="size-3.5 text-emerald-400" />
                  Signed Offline PDF
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
