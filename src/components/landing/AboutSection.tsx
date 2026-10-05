import { ShieldCheck, Building2, Atom, Zap, Lock, Layers, FileCheck, Cpu } from "lucide-react";

export function AboutSection() {
  const targetEnvironments = [
    {
      icon: ShieldCheck,
      sector: "Defense & Military Enclaves",
      purpose:
        "Protect tactical command centers, isolated weapons testing ranges, and classified defense networks against unauthorized physical media vectors and insider sabotage.",
    },
    {
      icon: Atom,
      sector: "Nuclear & Energy Infrastructure",
      purpose:
        "Monitor SCADA, safety telemetry, and reactor instrumentation networks requiring strict physical air gaps under nuclear safety regulations.",
    },
    {
      icon: Zap,
      sector: "Power Grids & Industrial Control",
      purpose:
        "Investigate substation automation, PLC communication logs, and industrial perimeter switches without risking grid disruption from external connections.",
    },
    {
      icon: Building2,
      sector: "Intelligence & Research Facilities",
      purpose:
        "Safeguard proprietary aerospace designs, national cryptographic laboratories, and isolated research archives from advanced persistent threats (APTs).",
    },
  ];

  return (
    <section id="about" className="py-16 lg:py-24 border-b border-slate-800/60 bg-[#050811]">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-1.5 rounded-full border border-slate-700 bg-slate-900/60 px-3 py-1 text-[11px] font-mono font-semibold text-slate-300">
            ABOUT ASEIOS-SOC
          </div>
          <h2 className="mt-3 text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
            Sovereign Security for Critical Infrastructure
          </h2>
          <p className="mt-4 text-sm sm:text-base leading-relaxed text-slate-400">
            ASEIOS-SOC (SynTrace AI) was engineered to bridge the gap between rigorous physical
            isolation and modern AI-augmented threat investigation.
          </p>
        </div>

        {/* Narrative Grid */}
        <div className="mt-12 grid lg:grid-cols-2 gap-8 items-center">
          <div className="space-y-4 text-xs sm:text-sm text-slate-300 leading-relaxed">
            <h3 className="text-xl font-bold text-white">
              Purpose-Built for Environments Where Cloud is Not an Option
            </h3>
            <p>
              In high-security enclaves, standard cyber incident response workflows break down.
              Analysts cannot upload suspicious memory dumps, event logs, or script contents to
              commercial cloud threat-intelligence services without violating national security
              classification guidelines and air-gap boundaries.
            </p>
            <p>
              ASEIOS-SOC packages the analytical capabilities of a modern Security Operations Center
              into a self-contained, offline-deployable stack. By pairing a deterministic 11-rule
              threat engine with locally hosted LLMs, the platform turns millions of cryptic event
              logs into understandable, human-readable attack narratives in seconds.
            </p>
            <div className="rounded-lg border border-slate-800 bg-[#090e1a] p-4 text-xs font-mono">
              <div className="text-cyan-400 font-bold mb-1">// CORE DESIGN COMMITMENT</div>
              <p className="text-slate-400">
                Every calculation, correlation cluster, risk score, and report is computed locally.
                The same log evidence will always produce the identical forensic conclusion.
              </p>
            </div>
          </div>

          {/* Enclave Target Sectors */}
          <div className="grid gap-3.5 sm:grid-cols-2">
            {targetEnvironments.map((env, i) => (
              <div
                key={i}
                className="rounded-lg border border-slate-800 bg-[#090e1a] p-4 flex flex-col justify-between hover:border-slate-700 transition-colors"
              >
                <div>
                  <div className="grid size-8 place-items-center rounded-md border border-cyan-500/30 bg-cyan-950/30 text-cyan-400 mb-3">
                    <env.icon className="size-4" />
                  </div>
                  <h4 className="text-xs font-bold text-white">{env.sector}</h4>
                  <p className="mt-1.5 text-[11px] text-slate-400 leading-relaxed">{env.purpose}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* System Technical Specifications Strip */}
        <div className="mt-12 rounded-xl border border-slate-800 bg-[#090e1a] p-6">
          <h4 className="font-mono text-xs uppercase font-bold text-slate-400 tracking-wider mb-4">
            Platform Technical Baseline
          </h4>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 text-xs font-mono">
            <div>
              <span className="text-slate-500 block text-[10px]">BACKEND ENGINE</span>
              <strong className="text-white">Java 21 LTS</strong>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">MICRO-FRAMEWORK</span>
              <strong className="text-white">Spring Boot 3.5</strong>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">ENCLAVE DATABASE</span>
              <strong className="text-white">PostgreSQL 16</strong>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">OFFLINE AI</span>
              <strong className="text-white">Ollama / Template</strong>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">ANALYST UI</span>
              <strong className="text-white">React 19 + Vite</strong>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">REPORT EXPORT</span>
              <strong className="text-white">Signed PDF / JSON</strong>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
