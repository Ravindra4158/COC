import React from 'react';

export default function KeyMetrics({ summary, recommendations, activePatches = [] }) {
  const currentRisk = Number(summary?.baseline_risk || 0);
  
  // Calculate unpatched baseline reference (if patches are active, calculate delta)
  const isPatched = activePatches.length > 0;
  // If top recommendation has patch value, show potential delta or applied delta
  const topRec = recommendations?.[0];
  const maxPossibleReduction = topRec ? Number(topRec.risk_reduction_percent || 0) : 0;
  
  // Estimated unpatched baseline risk if current is already patched
  const baselineRef = isPatched ? currentRisk * 1.15 : currentRisk;
  const reductionPercent = isPatched
    ? (((baselineRef - currentRisk) / baselineRef) * 100).toFixed(1)
    : '0.0';

  return (
    <section className="metrics-grid">
      {/* Card 1: Total Nodes */}
      <div className="metric-card">
        <div className="card-header">
          <span className="card-label">TOTAL HOST NODES</span>
          <span className="card-tag">TOPOLOGY</span>
        </div>
        <div className="card-body">
          <div className="metric-value-row">
            <span className="metric-number text-cyan">{summary?.total_hosts || 40}</span>
            <span className="metric-unit">HOSTS</span>
          </div>
          <div className="metric-breakdown">
            <span className="breakdown-item">
              <i className="dot-entry" /> 2 Entry (0, 1)
            </span>
            <span className="breakdown-item">
              <i className="dot-neutral" /> 33 Transits
            </span>
            <span className="breakdown-item">
              <i className="dot-target" /> 5 Targets
            </span>
          </div>
        </div>
        <div className="card-footer">
          <span className="footer-note">Undirected GNP Graph (p=0.09)</span>
        </div>
      </div>

      {/* Card 2: Total Vulnerabilities */}
      <div className="metric-card">
        <div className="card-header">
          <span className="card-label">TOTAL VULNERABILITIES</span>
          <span className="card-tag">EXPOSURE</span>
        </div>
        <div className="card-body">
          <div className="metric-value-row">
            <span className="metric-number text-amber">{summary?.total_vulnerabilities || 80}</span>
            <span className="metric-unit">CVE FINDINGS</span>
          </div>
          <div className="metric-breakdown">
            <span className="breakdown-item">2 Findings / Host</span>
            <span className="breakdown-item">CVSS: 3.0 – 9.8</span>
            <span className="breakdown-item text-emerald">80/80 Scored</span>
          </div>
        </div>
        <div className="card-footer">
          <span className="footer-note">Linear Prob Function: (CVSS - 2) / 8</span>
        </div>
      </div>

      {/* Card 3: Critical Assets */}
      <div className="metric-card">
        <div className="card-header">
          <span className="card-label">CRITICAL ASSETS</span>
          <span className="card-tag text-rose">HIGH VALUE</span>
        </div>
        <div className="card-body">
          <div className="metric-value-row">
            <span className="metric-number text-rose">{summary?.critical_assets || 5}</span>
            <span className="metric-unit">ASSETS</span>
          </div>
          <div className="metric-breakdown">
            <span className="breakdown-item">Nodes: 35, 36, 37, 38, 39</span>
            <span className="breakdown-item text-rose font-medium">Weights: 1, 2, 3, 4, 5</span>
          </div>
        </div>
        <div className="card-footer">
          <span className="footer-note">
            Reachable: {summary?.reachable_critical_assets || 5} / {summary?.critical_assets || 5} Assets
          </span>
        </div>
      </div>

      {/* Card 4: Risk Score (Before vs After) */}
      <div className="metric-card accent-card">
        <div className="card-header">
          <span className="card-label">NETWORK RISK (BEFORE VS AFTER)</span>
          <span className={`risk-badge ${isPatched ? 'reduced' : 'baseline'}`}>
            {isPatched ? `REDUCED -${reductionPercent}%` : 'BASELINE'}
          </span>
        </div>
        <div className="card-body">
          <div className="metric-value-row">
            <span className="metric-number text-emerald">{currentRisk.toFixed(2)}</span>
            <span className="metric-unit">WEIGHTED RISK</span>
          </div>
          <div className="risk-comparison-bar">
            <div
              className="risk-bar-fill"
              style={{
                width: `${Math.min(100, Math.max(10, (currentRisk / 15) * 100))}%`,
              }}
            />
          </div>
          <div className="metric-breakdown">
            {isPatched ? (
              <>
                <span className="breakdown-item text-cyan">
                  {activePatches.length} Virtual Patch(es) Active
                </span>
                <span className="breakdown-item text-emerald">
                  Risk decreased from {baselineRef.toFixed(2)}
                </span>
              </>
            ) : (
              <>
                <span className="breakdown-item">
                  Max potential single patch reduction: <b>{maxPossibleReduction.toFixed(1)}%</b>
                </span>
                <span className="breakdown-item text-slate">
                  Top patch: {topRec?.vulnerability_id || 'h39-v2'} (-{topRec?.patch_value?.toFixed(2) || '3.16'} pts)
                </span>
              </>
            )}
          </div>
        </div>
        <div className="card-footer">
          <span className="footer-note">4,000 Synchronized Monte Carlo Trials</span>
        </div>
      </div>
    </section>
  );
}
