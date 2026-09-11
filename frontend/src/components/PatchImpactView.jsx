import React from 'react';

function pathText(path) {
  if (Array.isArray(path)) return path.join(' → ');
  return String(path || '').replace(/[\[\],]/g, '').trim().replace(/\s+/g, ' → ');
}

export default function PatchImpactView({
  recommendations = [],
  activePatches = [],
  onTogglePatch,
  onSelectFinding,
  summary,
}) {
  const currentRisk = Number(summary?.baseline_risk || 0);

  return (
    <div className="patch-impact-page">
      {/* Top Banner */}
      <div className="view-banner">
        <div>
          <span className="panel-kicker">REMEDIATION ENGINE // PHASE 5</span>
          <h2 className="view-title">Top-10 Patch Recommendations</h2>
          <p className="view-subtitle">
            Ranked by true risk reduction toward critical assets (35–39) via 4,000 Synchronized Monte Carlo trials (Common Random Numbers).
          </p>
        </div>
        <div className="banner-stats">
          <div className="b-stat">
            <span className="b-label">CURRENT RISK</span>
            <span className="b-val text-emerald">{currentRisk.toFixed(2)}</span>
          </div>
          <div className="b-stat">
            <span className="b-label">ACTIVE PATCHES</span>
            <span className="b-val text-cyan">{activePatches.length} / 10</span>
          </div>
        </div>
      </div>

      {/* Grid of Top 10 Patch Cards */}
      <div className="patch-cards-grid">
        {recommendations.map((rec, index) => {
          const isPatched = activePatches.includes(rec.vulnerability_id);
          const pathStr = pathText(rec.associated_path);
          const reductionPct = Number(rec.risk_reduction_percent || 0).toFixed(1);
          const patchVal = Number(rec.patch_value || 0).toFixed(3);

          return (
            <div
              key={`${rec.host_id}-${rec.vulnerability_id}`}
              className={`patch-card ${isPatched ? 'card-patched' : ''} ${index < 3 ? 'top-tier' : ''}`}
              onClick={() => onSelectFinding?.(rec)}
            >
              <div className="card-top">
                <div className="rank-group">
                  <span className="rank-num">#{rec.rank || index + 1}</span>
                  {index < 3 && <span className="tier-tag">CRITICAL PRIORITY</span>}
                  {isPatched && <span className="patched-tag">PATCH ACTIVE</span>}
                </div>
                <div className="reduction-display">
                  <span className="red-pct">-{reductionPct}%</span>
                  <span className="red-sub">Risk Delta</span>
                </div>
              </div>

              <div className="card-main">
                <div className="vuln-header">
                  <span className="vuln-id-big">{rec.vulnerability_id}</span>
                  <span className="vuln-host-badge">HOST #{rec.host_id}</span>
                </div>

                <div className="card-stats-row">
                  <div>
                    <span className="cs-label">CVSS</span>
                    <b className="cs-val text-amber">{Number(rec.cvss).toFixed(1)}</b>
                  </div>
                  <div>
                    <span className="cs-label">EXPLOIT</span>
                    <b className="cs-val text-cyan">{(Number(rec.exploit_probability) * 100).toFixed(0)}%</b>
                  </div>
                  <div>
                    <span className="cs-label">PATCH VALUE</span>
                    <b className="cs-val text-emerald">{patchVal} pts</b>
                  </div>
                </div>

                {pathStr && (
                  <div className="path-box">
                    <span className="path-label">ATTACK WITNESS PATH:</span>
                    <span className="path-route">{pathStr}</span>
                  </div>
                )}

                <p className="card-explanation">
                  {rec.reason ||
                    `Patching ${rec.vulnerability_id} severs attacker reachability through host ${rec.host_id}, reducing network critical asset risk by ${reductionPct}%.`}
                </p>
              </div>

              <div className="card-actions">
                <button
                  className={`patch-toggle-btn ${isPatched ? 'btn-remove' : 'btn-apply'}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    onTogglePatch?.(rec.vulnerability_id);
                  }}
                >
                  {isPatched ? '✕ Remove Virtual Patch' : '⚡ Simulate Virtual Patch'}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
