import { Link } from "@tanstack/react-router";
import { Shield, Terminal, Cpu, Lock, ArrowRight } from "lucide-react";

export function Navbar() {
  return (
    <header className="sticky top-0 z-50 w-full border-b border-slate-800/80 bg-[#060a13]/90 backdrop-blur-md">
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        {/* Brand */}
        <Link to="/" className="flex items-center gap-2.5 group">
          <div className="grid size-8 place-items-center rounded-md border border-cyan-500/40 bg-cyan-950/40 text-cyan-400 group-hover:border-cyan-400 transition-colors shadow-xs">
            <Shield className="size-4" />
          </div>
          <div className="flex flex-col">
            <span className="font-mono text-sm font-extrabold tracking-wider text-white uppercase flex items-center gap-1.5">
              ASEIOS-SOC
              <span className="size-1.5 rounded-full bg-emerald-400 animate-pulse" />
            </span>
            <span className="text-[9px] font-mono tracking-widest text-slate-400 uppercase -mt-0.5">
              Air-Gapped Security Ops
            </span>
          </div>
        </Link>

        {/* Navigation links */}
        <nav className="hidden md:flex items-center gap-6 text-xs font-sans text-slate-400">
          <a href="#why" className="hover:text-slate-200 transition-colors">
            Why Air-Gap
          </a>
          <a href="#pipeline" className="hover:text-slate-200 transition-colors">
            Pipeline
          </a>
          <a href="#capabilities" className="hover:text-slate-200 transition-colors">
            Capabilities
          </a>
          <a href="#story" className="hover:text-slate-200 transition-colors">
            Attack Story
          </a>
          <a href="#architecture" className="hover:text-slate-200 transition-colors">
            Architecture
          </a>
          <a href="#about" className="hover:text-slate-200 transition-colors">
            About
          </a>
        </nav>

        {/* Actions & Launch Console CTA */}
        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-1.5 rounded-full border border-slate-800 bg-slate-900/60 px-2.5 py-1 text-[10px] font-mono text-slate-400">
            <Lock className="size-3 text-emerald-400" />
            <span>Air-Gap Active</span>
          </div>

          <Link
            to="/console"
            className="flex items-center gap-1.5 rounded-md border border-cyan-500/50 bg-cyan-950/50 px-3.5 py-1.5 text-xs font-semibold text-cyan-300 transition-all hover:border-cyan-400 hover:bg-cyan-900/50 hover:text-white shadow-xs"
          >
            <Terminal className="size-3.5 text-cyan-400" />
            <span>Launch SOC Console</span>
            <ArrowRight className="size-3" />
          </Link>
        </div>
      </div>
    </header>
  );
}
