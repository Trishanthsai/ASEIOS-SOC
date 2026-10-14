import React, { useState, useEffect } from "react";
import {
  QrCode,
  Radio,
  ShieldCheck,
  Zap,
  Play,
  Pause,
  RotateCcw,
  X,
  FileText,
  Lock,
  Eye,
  CheckCircle2,
} from "lucide-react";

interface OpticalDataDiodeModalProps {
  isOpen: boolean;
  onClose: () => void;
  evidenceHash?: string;
  incidentId?: string;
}

export function OpticalDataDiodeModal({
  isOpen,
  onClose,
  evidenceHash = "8f4b2b1a9e34c718a22d561e44f801bc3d2e99a11f54d68e7b99c012fa3829dc",
  incidentId = "AES-2026-8941",
}: OpticalDataDiodeModalProps) {
  const [frameIndex, setFrameIndex] = useState(0);
  const [isPlaying, setIsPlaying] = useState(true);

  // Frames for Animated Optical Diode
  const totalFrames = 6;

  useEffect(() => {
    if (!isOpen || !isPlaying) return;
    const interval = setInterval(() => {
      setFrameIndex((prev) => (prev + 1) % totalFrames);
    }, 250); // 4 FPS animation
    return () => clearInterval(interval);
  }, [isOpen, isPlaying]);

  if (!isOpen) return null;

  // Mock Optical High-Density Matrix Patterns for the animated QR stream
  const qrPatterns = [
    "M2 2h8v8H2zM14 2h8v8h-8zM2 14h8v8H2zM15 15h2v2h-2zM19 15h3v3h-3zM15 19h3v3h-3zM6 6h2v2H6zM18 6h2v2h-2zM6 18h2v2H6z",
    "M2 2h8v8H2zM14 2h8v8h-8zM2 14h8v8H2zM13 13h4v4h-4zM18 14h4v2h-4zM14 18h2v4h-2zM6 6h2v2H6zM18 6h2v2h-2zM6 18h2v2H6z",
    "M2 2h8v8H2zM14 2h8v8h-8zM2 14h8v8H2zM15 13h2v3h-2zM19 16h3v4h-3zM13 17h3v5h-3zM6 6h2v2H6zM18 6h2v2h-2zM6 18h2v2H6z",
    "M2 2h8v8H2zM14 2h8v8h-8zM2 14h8v8H2zM14 14h3v3h-3zM18 13h4v3h-4zM13 19h5v3h-5zM6 6h2v2H6zM18 6h2v2h-2zM6 18h2v2H6z",
    "M2 2h8v8H2zM14 2h8v8h-8zM2 14h8v8H2zM16 14h2v2h-2zM14 17h4v2h-4zM18 19h4v3h-4zM6 6h2v2H6zM18 6h2v2h-2zM6 18h2v2H6z",
    "M2 2h8v8H2zM14 2h8v8h-8zM2 14h8v8H2zM13 15h3v3h-3zM17 15h5v2h-5zM15 18h4v4h-4zM6 6h2v2H6zM18 6h2v2h-2zM6 18h2v2H6z",
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 p-4 backdrop-blur-md">
      <div className="w-full max-w-xl border border-purple-500/40 bg-[#090D16] p-6 rounded-lg shadow-2xl font-mono text-xs text-slate-300">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-purple-950 pb-3">
          <div className="flex items-center gap-2">
            <Radio className="size-5 text-purple-400 animate-pulse" />
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                Bi-Directional Optical Air-Gap Data Diode
                <span className="bg-purple-500/20 text-purple-400 border border-purple-500/40 text-[9px] px-2 py-0.5 rounded font-bold">
                  ZERO CABLE / ZERO RF
                </span>
              </h3>
              <p className="text-[10px] text-slate-400 font-sans mt-0.5">
                Physical one-way exfiltration via animated 2D Data Matrix stream. Eliminates USB Stuxnet infection vectors.
              </p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white cursor-pointer">
            <X className="size-4" />
          </button>
        </div>

        {/* Optical Stream Display */}
        <div className="mt-4 flex flex-col items-center justify-center bg-black/70 p-5 rounded border border-purple-900/50">
          <div className="relative p-4 bg-white rounded shadow-inner flex flex-col items-center">
            {/* SVG Matrix */}
            <svg
              className="size-44 text-black transition-all"
              viewBox="0 0 24 24"
              fill="currentColor"
            >
              <path d={qrPatterns[frameIndex]} />
            </svg>

            {/* Frame Badge */}
            <div className="mt-2 text-center text-[10px] text-black font-bold font-mono">
              FRAME {frameIndex + 1} OF {totalFrames} • CRC-32: 0x{((frameIndex + 1) * 7919).toString(16).toUpperCase()}
            </div>
          </div>

          <div className="mt-3 flex items-center gap-3">
            <button
              onClick={() => setIsPlaying(!isPlaying)}
              className="px-3 py-1 bg-purple-600/30 hover:bg-purple-600/50 text-purple-300 border border-purple-500/40 rounded flex items-center gap-1.5 text-[10px] font-bold uppercase cursor-pointer"
            >
              {isPlaying ? <Pause className="size-3" /> : <Play className="size-3" />}
              {isPlaying ? "Pause Stream" : "Resume Stream"}
            </button>
            <button
              onClick={() => setFrameIndex(0)}
              className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded flex items-center gap-1.5 text-[10px] font-bold uppercase cursor-pointer"
            >
              <RotateCcw className="size-3" /> Reset Frame
            </button>
          </div>
        </div>

        {/* Technical Explainer */}
        <div className="mt-4 space-y-2 text-[10.5px]">
          <div className="bg-black/50 p-3 rounded border border-slate-800 text-[10px] font-sans text-slate-300 leading-relaxed">
            <strong className="text-purple-300 font-mono block mb-1">
              PHYSICAL AIR-GAP SPECIFICATION (NATO / DEFENSE LEVEL 4):
            </strong>
            Instead of plugging in potentially weaponized USB sticks, the incident report payload and SHA-256 Chain of Custody certificate are encoded into an optical stream. An authorized officer’s smartphone or optical scanner reads the visual frames off the monitor in 2.8 seconds. <strong>Zero electrical contact, zero radio emission.</strong>
          </div>

          <div className="grid grid-cols-2 gap-2 text-[9.5px] font-mono">
            <div className="p-2 bg-slate-900/60 rounded border border-slate-800">
              <span className="text-slate-500 block">Incident ID</span>
              <span className="text-white font-bold">{incidentId}</span>
            </div>
            <div className="p-2 bg-slate-900/60 rounded border border-slate-800">
              <span className="text-slate-500 block">SHA-256 Digest</span>
              <span className="text-emerald-400 font-bold truncate block">{evidenceHash}</span>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-5 flex justify-end border-t border-slate-800 pt-3">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded font-bold uppercase text-[10px] cursor-pointer"
          >
            Close Diode
          </button>
        </div>
      </div>
    </div>
  );
}
