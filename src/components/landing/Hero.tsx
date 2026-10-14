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
  Crosshair,
  Calculator,
  Radar,
  Zap,
} from "lucide-react";

interface HeroProps {
  onOpenSimulator?: () => void;
  onOpenRoi?: () => void;
  onOpenCanary?: () => void;
}

export function Hero({ onOpenSimulator, onOpenRoi, onOpenCanary }: HeroProps) {
  return (
    <section className="relative overflow-hidden pt-12 pb-16 lg:pt-20 lg:pb-24 border-b border-slate-800/60 bg-[#030610]">
      {/* 1. Cyberattack Network Visualization Video Background */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        {/* Local Video Stream with Autoplay, Continuous Loop, Muted, Inline Playback */}
        <video
          autoPlay
          loop
          muted
          playsInline
          preload="auto"
          aria-hidden="true"
          className="absolute inset-0 h-full w-full object-cover object-center opacity-48 sm:opacity-54 contrast-[1.12] brightness-[1.06] motion-reduce:hidden transition-opacity duration-1000"
        >
          <source src="/videos/cyberattack-loop.mp4" type="video/mp4" />
        </video>

        {/* 2. Targeted Radial Vignette Overlay: Darker behind center text (0.84), lighter at sides & lower area (0.38) */}
        <div
          className="absolute inset-0"
          style={{
            background:
              "radial-gradient(ellipse 75% 55% at 50% 36%, rgba(3, 6, 16, 0.84) 0%, rgba(3, 6, 16, 0.62) 55%, rgba(3, 6, 16, 0.38) 100%)",
          }}
        />

        {/* Top & Bottom Seamless Edge Blend into Navbar and Subsequent Section */}
        <div className="absolute inset-0 bg-gradient-to-b from-[#030610]/90 via-transparent to-[#030610]" />

        {/* Subtle Radial Cyan/Indigo Accent Glow for Enclave Aesthetic */}
        <div
          className="absolute inset-0 opacity-35 mix-blend-screen"
          style={{
            backgroundImage: `radial-gradient(ellipse 65% 50% at 50% 15%, rgba(6, 182, 212, 0.22), transparent 75%)`,
          }}
        />

        {/* Precision Cybersecurity Scanline/Grid Overlay */}
        <div
          className="absolute inset-0 opacity-12"
          style={{
            backgroundImage: `
              linear-gradient(to right, rgba(51, 65, 85, 0.2) 1px, transparent 1px),
              linear-gradient(to bottom, rgba(51, 65, 85, 0.2) 1px, transparent 1px)
            `,
            backgroundSize: "32px 32px",
          }}
        />
      </div>

      {/* Foreground Content */}
      <div className="relative z-10 mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col items-center text-center">
          {/* Top Enclave Status Pill */}
          <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/30 bg-[#090f1d]/90 backdrop-blur-xs px-3.5 py-1 text-xs text-slate-300 shadow-sm mb-6">
            <span className="flex size-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="font-mono text-[11px] uppercase tracking-wider text-cyan-300 font-semibold">
              OFFLINE-FIRST ENCLAVE SOC // ZERO CLOUD EGRESS
            </span>
          </div>

          {/* Main Title */}
          <h1 className="max-w-4xl font-display text-4xl font-extrabold tracking-tight text-white sm:text-5xl lg:text-6xl leading-[1.12] drop-shadow-sm">
            Offline Intelligence for{" "}
            <span className="bg-gradient-to-r from-cyan-400 via-sky-300 to-indigo-400 bg-clip-text text-transparent">
              Air-Gapped Security
            </span>{" "}
            Operations
          </h1>

          {/* Subtitle / Value Proposition */}
          <p className="mt-5 max-w-2xl text-sm sm:text-base leading-relaxed text-slate-300 font-sans drop-shadow-xs">
            <strong>ASEIOS-SOC (SynTrace AI)</strong> ingests, normalizes, and reconstructs security
            telemetry within isolated defense and critical infrastructure enclaves. Perform
            deterministic rule-based threat detection, cross-host event correlation, forensic attack
            reconstruction, IOC analysis, MITRE ATT&CK mapping, and local AI investigation—without
            transmitting a single byte outside the physical perimeter.
          </p>

          {/* Visual Indicator Badges */}
          <div className="mt-7 flex flex-wrap justify-center gap-2 sm:gap-3">
            <span className="inline-flex items-center gap-1.5 rounded-md border border-cyan-500/30 bg-cyan-950/40 backdrop-blur-xs px-3 py-1.5 text-xs font-mono font-semibold text-cyan-300 shadow-xs">
              <Lock className="size-3.5 text-cyan-400" />
              AIR-GAPPED SOVEREIGNTY
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-md border border-indigo-500/30 bg-indigo-950/40 backdrop-blur-xs px-3 py-1.5 text-xs font-mono font-semibold text-indigo-300 shadow-xs">
              <Cpu className="size-3.5 text-indigo-400" />
              LOCAL AI (OLLAMA / DETERMINISTIC)
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/30 bg-emerald-950/40 backdrop-blur-xs px-3 py-1.5 text-xs font-mono font-semibold text-emerald-300 shadow-xs">
              <Radio className="size-3.5 text-emerald-400" />
              ZERO EXTERNAL DEPENDENCIES
            </span>
          </div>

          {/* Primary CTAs */}
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3.5">
            <Link
              to="/console"
              className="inline-flex items-center gap-2 rounded-lg bg-cyan-600 px-6 py-3 text-sm font-bold text-white shadow-lg shadow-cyan-950/60 hover:bg-cyan-500 transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              <Terminal className="size-4" />
              <span>Launch SOC Console</span>
              <ArrowRight className="size-4" />
            </Link>

            {onOpenSimulator && (
              <button
                onClick={onOpenSimulator}
                className="inline-flex items-center gap-2 rounded-lg border border-cyan-500/40 bg-cyan-950/40 backdrop-blur-xs px-5 py-3 text-sm font-semibold text-cyan-300 hover:border-cyan-400 hover:bg-cyan-900/50 hover:text-white transition-all cursor-pointer shadow-xs"
              >
                <Crosshair className="size-4 text-cyan-400" />
                <span>Simulate Attack (48+)</span>
              </button>
            )}

            {onOpenRoi && (
              <button
                onClick={onOpenRoi}
                className="inline-flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-950/40 backdrop-blur-xs px-5 py-3 text-sm font-semibold text-emerald-300 hover:border-emerald-400 hover:bg-emerald-900/50 hover:text-white transition-all cursor-pointer shadow-xs"
              >
                <Calculator className="size-4 text-emerald-400" />
                <span>Calculate TCO Savings</span>
              </button>
            )}

            <a
              href="#architecture"
              className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-850/80 backdrop-blur-xs px-5 py-3 text-sm font-semibold text-slate-300 hover:border-slate-600 hover:bg-slate-800 hover:text-white transition-all"
            >
              <span>Explore System Flow</span>
            </a>
          </div>

          {/* Live Enclave Telemetry Card Preview */}
          <div className="mt-12 w-full max-w-4xl rounded-xl border border-slate-800 bg-[#070c17]/90 backdrop-blur-md p-4 text-left shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
              <div className="flex items-center gap-2">
                <span className="size-3 rounded-full bg-red-500/60 inline-block" />
                <span className="size-3 rounded-full bg-yellow-500/60 inline-block" />
                <span className="size-3 rounded-full bg-green-500/60 inline-block" />
                <span className="ml-2 font-mono text-[11px] text-slate-400">
                  enclave-terminal // DRDO-NPCIL-SECURE-ENCLAVE
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="rounded bg-emerald-950/50 px-2 py-0.5 font-mono text-[10px] text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                  <span className="size-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  AIR-GAP LOCKED
                </span>
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="rounded border border-slate-800/80 bg-slate-950/70 p-3">
                <div className="text-[10px] uppercase text-slate-500 font-bold">
                  Boundary Egress
                </div>
                <div className="mt-1 font-bold text-red-400 flex items-center gap-1.5">
                  <span className="size-1.5 rounded-full bg-red-400 animate-pulse" />
                  BLOCKED (0 B/s)
                </div>
              </div>

              <div className="rounded border border-slate-800/80 bg-slate-950/70 p-3">
                <div className="text-[10px] uppercase text-slate-500 font-bold">Active Rules</div>
                <div className="mt-1 font-bold text-cyan-400 flex items-center gap-1.5">
                  <Activity className="size-3.5 text-cyan-400" />
                  11 MITRE Rules
                </div>
              </div>

              <div className="rounded border border-slate-800/80 bg-slate-950/70 p-3">
                <div className="text-[10px] uppercase text-slate-500 font-bold">AI Narrative</div>
                <div className="mt-1 font-bold text-indigo-300 flex items-center gap-1.5">
                  <Cpu className="size-3.5 text-indigo-400" />
                  Ollama / Local Fallback
                </div>
              </div>

              <div className="rounded border border-slate-800/80 bg-slate-950/70 p-3">
                <div className="text-[10px] uppercase text-slate-500 font-bold">
                  Deception Traps
                </div>
                <div className="mt-1 font-bold text-emerald-400 flex items-center gap-1.5">
                  <Radar className="size-3.5 text-emerald-400" />4 Honey-Canaries Armed
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
