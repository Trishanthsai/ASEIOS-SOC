import React from "react";
import { useScrollReveal } from "@/hooks/useScrollReveal";

interface ScrollRevealProps {
  children: React.ReactNode;
  className?: string;
  delay?: number; // milliseconds
  direction?: "up" | "down" | "left" | "right" | "none";
  threshold?: number;
}

export function ScrollReveal({
  children,
  className = "",
  delay = 0,
  direction = "up",
  threshold = 0.1,
}: ScrollRevealProps) {
  const { ref, isVisible } = useScrollReveal({ threshold });

  const getInitialTransform = () => {
    switch (direction) {
      case "up":
        return "translate-y-8";
      case "down":
        return "-translate-y-8";
      case "left":
        return "translate-x-8";
      case "right":
        return "-translate-x-8";
      case "none":
        return "";
    }
  };

  return (
    <div
      ref={ref}
      style={{
        transitionDelay: `${delay}ms`,
      }}
      className={`transition-all duration-700 ease-[cubic-bezier(0.16,1,0.3,1)] motion-reduce:transition-none motion-reduce:transform-none motion-reduce:opacity-100 ${
        isVisible
          ? "opacity-100 translate-x-0 translate-y-0"
          : `opacity-0 ${getInitialTransform()}`
      } ${className}`}
    >
      {children}
    </div>
  );
}
