import React, { useEffect, useState } from 'react';

export default function SplashLanding({ onComplete }) {
  const [fading, setFading] = useState(false);

  useEffect(() => {
    // Begin smooth fade-out at 2400ms (0.4s before completion)
    const fadeTimer = setTimeout(() => {
      setFading(true);
    }, 2400);

    // Exactly 2800ms (2.8s) total duration before transitioning to main app
    const exitTimer = setTimeout(() => {
      onComplete?.();
    }, 2800);

    return () => {
      clearTimeout(fadeTimer);
      clearTimeout(exitTimer);
    };
  }, [onComplete]);

  const handleSkip = () => {
    setFading(true);
    setTimeout(() => {
      onComplete?.();
    }, 200);
  };

  return (
    <div className={`splash-overlay ${fading ? 'splash-fading' : ''}`}>
      {/* Background Cyber Grid Effect */}
      <div className="splash-cyber-grid" />
      <div className="splash-glow-orb splash-glow-left" />
      <div className="splash-glow-orb splash-glow-right" />

      {/* Top Banner Bar */}
      <div className="splash-topbar">
        <div className="splash-pill">
          <span className="splash-dot pulse" />
          <span>INITIALIZING DEFENSE NETWORK // ENCLAVE-ALPHA</span>
        </div>
        <button className="splash-skip-btn" onClick={handleSkip} title="Skip to dashboard">
          ENTER NOW &rarr;
        </button>
      </div>

      {/* Main 3-Column Content Layout */}
      <div className="splash-container">
        {/* Left Side: Short, Simple Description */}
        <div className="splash-left">
          <span className="splash-kicker">CYBERGRAPH INTELLIGENCE</span>
          <h2 className="splash-headline">Attack-Path-Aware Prioritization</h2>
          <p className="splash-description">
            Prioritize and patch vulnerabilities that sever critical attack paths before adversaries reach your high-value assets.
          </p>
          <div className="splash-features">
            <div className="splash-feature-chip">
              <span className="chip-icon">🛡️</span>
              <span>Choke Point Path Severing</span>
            </div>
            <div className="splash-feature-chip">
              <span className="chip-icon">⚡</span>
              <span>Measured Risk Reduction</span>
            </div>
            <div className="splash-feature-chip">
              <span className="chip-icon">🎯</span>
              <span>Synchronized Attack Simulation</span>
            </div>
          </div>
        </div>

        {/* Center: System Logo and RISK-PATCH Name */}
        <div className="splash-center">
          <div className="splash-logo-wrap">
            <div className="splash-logo-halo" />
            <div className="splash-logo-shield">
              <svg viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="currentColor" strokeWidth="1.8">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="url(#shieldGrad)" />
                <path d="M9 12l2 2 4-4" stroke="#00f0ff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
                <defs>
                  <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stopColor="#00f0ff" />
                    <stop offset="100%" stopColor="#10b981" />
                  </linearGradient>
                </defs>
              </svg>
            </div>
          </div>

          <h1 className="splash-title">RISK-PATCH</h1>
          <span className="splash-sub">PROACTIVE VIRTUAL REMEDIATION PLATFORM</span>

          {/* Progress loader bar (completes in 2.8s) */}
          <div className="splash-loader-bar">
            <div className="splash-loader-progress" />
          </div>
          <span className="splash-loader-text">SYNCHRONIZING ATTACK GRAPHS · 2.8s</span>
        </div>

        {/* Right Side: Network Graph Visualization Preview Teaser */}
        <div className="splash-right">
          <div className="splash-graph-card">
            <div className="splash-graph-head">
              <span className="splash-graph-label">TOPOLOGY PREVIEW</span>
              <span className="splash-graph-status">40 NODES · LIVE</span>
            </div>

            <div className="splash-svg-wrap">
              <svg viewBox="0 0 280 200" className="splash-network-svg">
                {/* Attack Path Edges */}
                <line x1="40" y1="50" x2="100" y2="90" className="edge-line edge-pulse" />
                <line x1="40" y1="150" x2="100" y2="90" className="edge-line" />
                <line x1="100" y1="90" x2="160" y2="60" className="edge-line edge-pulse" />
                <line x1="100" y1="90" x2="165" y2="140" className="edge-line" />
                <line x1="160" y1="60" x2="235" y2="70" className="edge-line edge-blocked" />
                <line x1="165" y1="140" x2="235" y2="150" className="edge-line edge-pulse" />
                <line x1="160" y1="60" x2="165" y2="140" className="edge-line" />

                {/* Entry Points (Green) */}
                <g className="node-group">
                  <circle cx="40" cy="50" r="14" className="svg-node node-entry" />
                  <circle cx="40" cy="50" r="20" className="svg-halo halo-entry" />
                  <text x="40" y="54" className="node-text">0</text>
                  <text x="40" y="30" className="node-sub-text">ENTRY</text>
                </g>

                <g className="node-group">
                  <circle cx="40" cy="150" r="14" className="svg-node node-entry" />
                  <circle cx="40" cy="150" r="20" className="svg-halo halo-entry" />
                  <text x="40" y="154" className="node-text">1</text>
                  <text x="40" y="176" className="node-sub-text">ENTRY</text>
                </g>

                {/* Transit Choke Point (Amber) */}
                <g className="node-group">
                  <circle cx="100" cy="90" r="14" className="svg-node node-transit" />
                  <text x="100" y="94" className="node-text">29</text>
                  <text x="100" y="70" className="node-sub-text text-amber">CHOKE</text>
                </g>

                {/* Virtual Patched Node (Cyan) */}
                <g className="node-group">
                  <circle cx="160" cy="60" r="15" className="svg-node node-patched" />
                  <circle cx="160" cy="60" r="22" className="svg-halo halo-patched" />
                  <text x="160" y="64" className="node-text">26</text>
                  <text x="160" y="38" className="node-sub-text text-cyan">PATCHED</text>
                </g>

                {/* Vulnerable Transit (Yellow/Amber) */}
                <g className="node-group">
                  <circle cx="165" cy="140" r="13" className="svg-node node-vuln" />
                  <text x="165" y="144" className="node-text">12</text>
                  <text x="165" y="165" className="node-sub-text">VULN</text>
                </g>

                {/* Critical Assets (Red/Rose) */}
                <g className="node-group">
                  <circle cx="235" cy="70" r="16" className="svg-node node-critical" />
                  <circle cx="235" cy="70" r="23" className="svg-halo halo-critical" />
                  <text x="235" y="74" className="node-text">39</text>
                  <text x="235" y="46" className="node-sub-text text-rose">CRIT #39</text>
                </g>

                <g className="node-group">
                  <circle cx="235" cy="150" r="15" className="svg-node node-critical" />
                  <circle cx="235" cy="150" r="21" className="svg-halo halo-critical" />
                  <text x="235" y="154" className="node-text">36</text>
                  <text x="235" y="178" className="node-sub-text text-rose">CRIT #36</text>
                </g>
              </svg>
            </div>

            <div className="splash-graph-legend">
              <span className="s-leg"><span className="s-dot s-green" /> Entry</span>
              <span className="s-leg"><span className="s-dot s-cyan" /> Patched</span>
              <span className="s-leg"><span className="s-dot s-amber" /> Choke</span>
              <span className="s-leg"><span className="s-dot s-rose" /> Critical</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
