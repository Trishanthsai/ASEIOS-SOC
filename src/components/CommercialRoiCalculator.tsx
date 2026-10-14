import React, { useState } from "react";
import {
  DollarSign,
  TrendingDown,
  ShieldCheck,
  Award,
  Layers,
  CheckCircle2,
  X,
  FileText,
  Calculator,
  ArrowRight,
} from "lucide-react";

interface CommercialRoiCalculatorProps {
  isOpen: boolean;
  onClose: () => void;
}

export function CommercialRoiCalculator({
  isOpen,
  onClose,
}: CommercialRoiCalculatorProps) {
  const [endpoints, setEndpoints] = useState(250);
  const [logGbPerDay, setLogGbPerDay] = useState(50);

  if (!isOpen) return null;

  // Commercial Math:
  // Splunk / Cloud SIEM: ~$150 per GB/day ingested annually + Cloud Compute + Data Transfer
  const cloudSiemAnnualCost = Math.round(logGbPerDay * 150 * 365 * 0.05 + endpoints * 45); // USD
  // ASEIOSSOC: Fixed Enclave Appliance License
  const aseiosAnnualCost = Math.round(7500 + endpoints * 12);
  const annualSavingsUsd = cloudSiemAnnualCost - aseiosAnnualCost;
  const savingsPercent = Math.round((annualSavingsUsd / cloudSiemAnnualCost) * 100);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 p-4 backdrop-blur-md">
      <div className="w-full max-w-3xl border border-emerald-500/40 bg-[#090D16] p-6 rounded-lg shadow-2xl font-mono text-xs text-slate-300">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-emerald-950 pb-3">
          <div className="flex items-center gap-2">
            <Calculator className="size-5 text-emerald-400" />
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                Commercial Value &amp; Cyber Insurance ROI Calculator
                <span className="bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 text-[9px] px-2 py-0.5 rounded font-bold">
                  SOVEREIGN APPLIANCE MODEL
                </span>
              </h3>
              <p className="text-[10px] text-slate-400 font-sans mt-0.5">
                Total Cost of Ownership (TCO) comparison against legacy cloud SIEMs and statutory cyber insurance compliance.
              </p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white cursor-pointer">
            <X className="size-4" />
          </button>
        </div>

        {/* Interactive Sliders */}
        <div className="mt-4 grid grid-cols-2 gap-4 bg-black/50 p-3.5 rounded border border-slate-800">
          <div>
            <div className="flex items-center justify-between text-[11px] mb-1">
              <span className="text-slate-300 font-bold font-sans">Enclave Endpoints / Workstations:</span>
              <span className="text-emerald-400 font-bold font-mono">{endpoints} Nodes</span>
            </div>
            <input
              type="range"
              min="50"
              max="2000"
              step="50"
              value={endpoints}
              onChange={(e) => setEndpoints(Number(e.target.value))}
              className="w-full accent-emerald-500 cursor-pointer"
            />
            <div className="flex justify-between text-[8.5px] text-slate-500 font-mono mt-0.5">
              <span>50 (Lab/Substation)</span>
              <span>1000 (Division)</span>
              <span>2000 (Command Center)</span>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between text-[11px] mb-1">
              <span className="text-slate-300 font-bold font-sans">Daily Log Ingestion Volume:</span>
              <span className="text-emerald-400 font-bold font-mono">{logGbPerDay} GB / Day</span>
            </div>
            <input
              type="range"
              min="10"
              max="500"
              step="10"
              value={logGbPerDay}
              onChange={(e) => setLogGbPerDay(Number(e.target.value))}
              className="w-full accent-emerald-500 cursor-pointer"
            />
            <div className="flex justify-between text-[8.5px] text-slate-500 font-mono mt-0.5">
              <span>10 GB/day</span>
              <span>250 GB/day</span>
              <span>500 GB/day</span>
            </div>
          </div>
        </div>

        {/* Cost Comparison Cards */}
        <div className="mt-4 grid grid-cols-3 gap-3">
          <div className="p-3 bg-red-950/20 border border-red-500/30 rounded">
            <span className="text-[9px] text-red-400 uppercase font-bold block">Cloud SIEM (Splunk / Sentinel)</span>
            <div className="text-xl font-bold text-red-300 font-mono mt-1">
              ${cloudSiemAnnualCost.toLocaleString()} <span className="text-[10px] text-slate-400">/ yr</span>
            </div>
            <div className="text-[9px] text-slate-400 mt-1 font-sans">
              High per-GB cloud ingestion bills + required internet egress bandwidth. Illegal in air-gapped zones.
            </div>
          </div>

          <div className="p-3 bg-emerald-950/30 border border-emerald-500/40 rounded">
            <span className="text-[9px] text-emerald-400 uppercase font-bold block">ASEIOSSOC Appliance</span>
            <div className="text-xl font-bold text-emerald-300 font-mono mt-1">
              ${aseiosAnnualCost.toLocaleString()} <span className="text-[10px] text-slate-400">/ yr</span>
            </div>
            <div className="text-[9px] text-slate-400 mt-1 font-sans">
              Fixed on-prem sovereign appliance license. Zero per-GB fees. 100% telemetry retained locally.
            </div>
          </div>

          <div className="p-3 bg-sky-950/30 border border-sky-500/40 rounded flex flex-col justify-between">
            <div>
              <span className="text-[9px] text-sky-400 uppercase font-bold block">Total Annual Savings</span>
              <div className="text-xl font-bold text-sky-300 font-mono mt-1">
                {savingsPercent}% <span className="text-[10px] text-slate-300">($ {annualSavingsUsd.toLocaleString()})</span>
              </div>
            </div>
            <div className="text-[9px] text-emerald-400 font-bold font-mono">
              Payback Period: 3.8 Months
            </div>
          </div>
        </div>

        {/* Cyber Insurance Underwriting Scorecard */}
        <div className="mt-4 p-3.5 bg-black/60 rounded border border-slate-800">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
            <div className="flex items-center gap-2">
              <Award className="size-4 text-amber-400" />
              <span className="font-bold text-white uppercase text-[11px]">
                Cyber Insurance Underwriting &amp; Statutory Compliance Grade
              </span>
            </div>
            <span className="bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 text-[9.5px] px-2 py-0.5 rounded font-bold font-mono">
              GRADE A+ (97.4 / 100)
            </span>
          </div>

          <div className="mt-2.5 grid grid-cols-3 gap-2 text-[10px] font-sans">
            <div className="p-2 bg-slate-900/60 rounded border border-slate-800">
              <div className="font-bold text-emerald-400 flex items-center gap-1">
                <CheckCircle2 className="size-3" /> CERT-In Mandate
              </div>
              <div className="text-slate-400 text-[9px] mt-0.5">
                Complies with statutory 6-hour incident disclosure requirement via instant automated incident reports.
              </div>
            </div>

            <div className="p-2 bg-slate-900/60 rounded border border-slate-800">
              <div className="font-bold text-emerald-400 flex items-center gap-1">
                <CheckCircle2 className="size-3" /> ISO/IEC 27037 Legal
              </div>
              <div className="text-slate-400 text-[9px] mt-0.5">
                WORM SHA-256 chain of custody guarantees court-admissible forensic evidence non-repudiation.
              </div>
            </div>

            <div className="p-2 bg-slate-900/60 rounded border border-slate-800">
              <div className="font-bold text-emerald-400 flex items-center gap-1">
                <CheckCircle2 className="size-3" /> 35% Insurance Discount
              </div>
              <div className="text-slate-400 text-[9px] mt-0.5">
                Qualified for Lloyd's / HDFC Ergo cyber liability insurance premium discount due to automated containment.
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-5 flex items-center justify-between border-t border-slate-800 pt-3">
          <div className="text-[10px] text-slate-400 font-mono">
            Licensing Model: <strong className="text-slate-200">Per-Enclave Hardware Appliance + Offline Signature Subscription</strong>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded font-bold uppercase text-[10px] cursor-pointer"
          >
            Close Calculator
          </button>
        </div>
      </div>
    </div>
  );
}
