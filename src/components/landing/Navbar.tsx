import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { Shield, Terminal, Cpu, Lock, ArrowRight, Menu, X, Radio } from "lucide-react";

export function Navbar() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navLinks = [
    { href: "#why", label: "Why Air-Gap" },
    { href: "#enclave-tech", label: "Breakthrough Tech" },
    { href: "#pipeline", label: "Pipeline" },
    { href: "#capabilities", label: "Capabilities" },
    { href: "#architecture", label: "Architecture" },
    { href: "#story", label: "Attack Story" },
    { href: "#about", label: "About" },
  ];

  return (
    <header className="sticky top-0 z-50 w-full border-b border-slate-800/80 bg-[#040811]/90 backdrop-blur-md">
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
              Air-Gapped Enclave Intelligence
            </span>
          </div>
        </Link>

        {/* Desktop Navigation links */}
        <nav className="hidden lg:flex items-center gap-6 text-xs font-sans text-slate-400">
          {navLinks.map((link) => (
            <a
              key={link.href}
              href={link.href}
              className="hover:text-cyan-300 transition-colors font-medium"
            >
              {link.label}
            </a>
          ))}
        </nav>

        {/* Actions & Launch Console CTA */}
        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-1.5 rounded-full border border-slate-800 bg-slate-900/60 px-2.5 py-1 text-[10px] font-mono text-slate-400">
            <Lock className="size-3 text-emerald-400" />
            <span>Air-Gap Locked</span>
          </div>

          <Link
            to="/console"
            className="flex items-center gap-1.5 rounded-md border border-cyan-500/50 bg-cyan-950/50 px-3.5 py-1.5 text-xs font-semibold text-cyan-300 transition-all hover:border-cyan-400 hover:bg-cyan-900/50 hover:text-white shadow-xs"
          >
            <Terminal className="size-3.5 text-cyan-400" />
            <span>Launch Console</span>
            <ArrowRight className="size-3" />
          </Link>

          {/* Mobile menu toggle */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="grid size-8 place-items-center rounded-md border border-slate-800 text-slate-400 hover:text-white lg:hidden cursor-pointer"
            aria-label="Toggle Navigation Menu"
          >
            {mobileMenuOpen ? <X className="size-4" /> : <Menu className="size-4" />}
          </button>
        </div>
      </div>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="lg:hidden border-b border-slate-800 bg-[#060a15] px-4 py-4 space-y-2">
          {navLinks.map((link) => (
            <a
              key={link.href}
              href={link.href}
              onClick={() => setMobileMenuOpen(false)}
              className="block rounded-md px-3 py-2 text-xs font-mono text-slate-300 hover:bg-slate-900 hover:text-cyan-300 transition-colors"
            >
              {link.label}
            </a>
          ))}
          <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
            <span className="flex items-center gap-1.5">
              <span className="size-2 rounded-full bg-emerald-400" />
              Air-Gap Active // Zero Egress
            </span>
            <span className="text-cyan-400 font-bold">v2026.Q4</span>
          </div>
        </div>
      )}
    </header>
  );
}
