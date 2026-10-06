import React from 'react';

export default function RadialScoreGauge({ score = 0, size = 96 }) {
  const normalizedScore = Math.max(0, Math.min(100, score));
  const radius = 36;
  const circumference = 2 * Math.PI * radius; // ~226.195
  const strokeOffset = circumference - (circumference * normalizedScore) / 100;

  let strokeColor = '#10B981'; // Low / Clean (Emerald Green)
  if (normalizedScore > 50) {
    strokeColor = '#EF4444'; // Critical / High (Red)
  } else if (normalizedScore > 20) {
    strokeColor = '#F97316'; // Medium (Amber Orange)
  }

  return (
    <div className="relative flex items-center justify-center shrink-0" style={{ width: size, height: size }}>
      <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
        {/* Track Circle */}
        <circle
          cx="50"
          cy="50"
          r={radius}
          fill="none"
          stroke="#1F1F1F"
          strokeWidth="7"
        />
        {/* Functional Filled Arc */}
        <circle
          cx="50"
          cy="50"
          r={radius}
          fill="none"
          stroke={strokeColor}
          strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokeOffset}
          className="transition-all duration-700 ease-out"
        />
      </svg>
      <div className="absolute flex flex-col items-center justify-center">
        <span className="text-xl font-bold font-mono leading-none" style={{ color: strokeColor }}>
          {normalizedScore}
        </span>
        <span className="text-[10px] font-mono text-[#737373] mt-0.5">/100</span>
      </div>
    </div>
  );
}
