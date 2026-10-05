import { Link } from "@tanstack/react-router";
import { Terminal, Shield, ArrowRight, Lock, Radio } from "lucide-react";

export function Footer() {
  return (
    <footer className="bg-[#03060d] text-slate-400">
      {/* Pre-footer Call-To-Action Banner */}
      <div className="border-b border-slate-800/80 bg-gradient-to-b from-[#070d1a] to-[#040812] py-16">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 text-center">
          <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/40 bg-cyan-950/30 px-3 py-1 text-xs text-cyan-300 font-mono mb-4">
            <span className="size-2 rounded-full bg-cyan-400 animate-pulse" />
            STANDALONE WORKSPACE READY
          </div>

          <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
            Ready to Investigate?
          </h2>

          <p className="mt-3 text-sm text-slate-400 max-w-xl mx-auto leading-relaxed">
            Open the analyst workspace, ingest sample or live security evidence, examine correlated
            attack timelines, and converse with the local offline assistant.
          </p>

          <div className="mt-8 flex justify-center">
            <Link
              to="/console"
              className="inline-flex items-center gap-2 rounded-md bg-cyan-600 px-8 py-3.5 text-sm font-bold text-white shadow-xl shadow-cyan-950/60 hover:bg-cyan-500 transition-all hover:scale-105 active:scale-95"
            >
              <Terminal className="size-4" />
              <span>Launch SOC Console</span>
              <ArrowRight className="size-4" />
            </Link>
          </div>
        </div>
      </div>

      {/* Main Footer Links & Meta */}
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-10">
        <div className="flex flex-wrap items-center justify-between gap-6 border-b border-slate-850 pb-8">
          <div className="flex items-center gap-2.5">
            <div className="grid size-8 place-items-center rounded border border-cyan-500/40 bg-cyan-950/40 text-cyan-400">
              <Shield className="size-4" />
            </div>
            <div>
              <span className="font-mono text-sm font-extrabold text-white uppercase block">
                ASEIOS-SOC
              </span>
              <span className="text-[10px] text-slate-500 font-mono">
                Offline AI-Powered Security Operations Center
              </span>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-6 text-xs font-sans">
            <a href="#why" className="hover:text-white transition-colors">
              Why Air-Gap
            </a>
            <a href="#pipeline" className="hover:text-white transition-colors">
              Pipeline
            </a>
            <a href="#capabilities" className="hover:text-white transition-colors">
              Capabilities
            </a>
            <a href="#story" className="hover:text-white transition-colors">
              Attack Story
            </a>
            <a href="#architecture" className="hover:text-white transition-colors">
              Architecture
            </a>
            <a href="#about" className="hover:text-white transition-colors">
              About
            </a>
            <Link to="/console" className="text-cyan-400 hover:text-cyan-300 font-semibold">
              Analyst Console
            </Link>
          </div>
        </div>

        <div className="pt-6 flex flex-wrap items-center justify-between gap-4 text-xs font-mono text-slate-500">
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1.5 text-emerald-400">
              <Lock className="size-3" /> Air-Gapped Mode
            </span>
            <span className="flex items-center gap-1.5 text-red-400">
              <Radio className="size-3" /> Egress Blocked
            </span>
          </div>

          <div>
            <span>© 2026 ASEIOS-SOC (SynTrace AI). Enclave Deployment Edition.</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
