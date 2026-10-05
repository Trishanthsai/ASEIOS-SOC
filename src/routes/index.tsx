import { createFileRoute } from "@tanstack/react-router";
import { Navbar } from "@/components/landing/Navbar";
import { Hero } from "@/components/landing/Hero";
import { WhySection } from "@/components/landing/WhySection";
import { PipelineSection } from "@/components/landing/PipelineSection";
import { CapabilitiesSection } from "@/components/landing/CapabilitiesSection";
import { AttackStoryShowcase } from "@/components/landing/AttackStoryShowcase";
import { ArchitectureSection } from "@/components/landing/ArchitectureSection";
import { AboutSection } from "@/components/landing/AboutSection";
import { Footer } from "@/components/landing/Footer";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "ASEIOS-SOC — Offline Intelligence for Air-Gapped Security" },
      {
        name: "description",
        content:
          "Offline AI-Powered Security Operations Center for Air-Gapped and Isolated Networks.",
      },
    ],
  }),
  component: LandingPage,
});

export function LandingPage() {
  return (
    <div className="min-h-screen bg-[#040811] text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-white">
      <Navbar />
      <main className="flex-1">
        <Hero />
        <WhySection />
        <PipelineSection />
        <CapabilitiesSection />
        <AttackStoryShowcase />
        <ArchitectureSection />
        <AboutSection />
      </main>
      <Footer />
    </div>
  );
}
