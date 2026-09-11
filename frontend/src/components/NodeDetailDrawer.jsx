import React from 'react';

export default function NodeDetailDrawer({
  node,
  vulnerabilities = [],
  network,
  activePatches = [],
  onTogglePatch,
  onClose,
}) {
  if (!node) return null;

  const idNum = Number(node.id);
  const isEntry = [0, 1].includes(idNum);
  const isCritical = [35, 36, 37, 38, 39].includes(idNum);
  const nodeVulns = vulnerabilities.filter(v => String(v.host_id) === String(node.id));

  // Find neighbors from network edges
  const neighbors = (network?.edges || [])
    .filter(e => String(e.source) === String(node.id) || String(e.target) === String(node.id))
    .map(e => (String(e.source) === String(node.id) ? e.target : e.source));

  return (
    <aside className="node-detail-drawer">
      <div className="drawer-header">
        <div className="drawer-title-group">
          <span className="drawer-kicker">NODE INSPECTION</span>
          <h3 className="drawer-node-id">Host Node #{node.id}</h3>
        </div>
        <button className="drawer-close-btn" onClick={onClose} title="Close inspector">
          ✕
        </button>
      </div>

      <div className="drawer-body">
        {/* Node Type Badges */}
        <div className="drawer-type-tags">
          {isEntry && <span className="drawer-tag tag-entry">ATTACK ENTRY NODE</span>}
          {isCritical && <span className="drawer-tag tag-crit">CRITICAL ASSET #{idNum}</span>}
          {!isEntry && !isCritical && <span className="drawer-tag tag-transit">TRANSIT NODE</span>}
          <span className="drawer-tag tag-degree">{neighbors.length} EDGES</span>
        </div>

        {/* Node Properties */}
        <div className="drawer-stats-grid">
          <div className="d-stat">
            <span className="d-label">DEGREE</span>
            <span className="d-val">{neighbors.length}</span>
          </div>
          <div className="d-stat">
            <span className="d-label">VULNERABILITIES</span>
            <span className="d-val text-amber">{nodeVulns.length}</span>
          </div>
          <div className="d-stat">
            <span className="d-label">MAX CVSS</span>
            <span className="d-val text-rose">
              {nodeVulns.length ? Math.max(...nodeVulns.map(v => Number(v.cvss || 0))).toFixed(1) : '0.0'}
            </span>
          </div>
          <div className="d-stat">
            <span className="d-label">EXPLOIT PROB</span>
            <span className="d-val text-cyan">
              {nodeVulns.length ? `${(Math.max(...nodeVulns.map(v => Number(v.exploit_probability || 0))) * 100).toFixed(0)}%` : '0%'}
            </span>
          </div>
        </div>

        {/* Connected Neighbors list */}
        <div className="drawer-section">
          <span className="drawer-section-title">ADJACENT HOSTS ({neighbors.length})</span>
          <div className="neighbors-chip-row">
            {neighbors.map((nbr, idx) => (
              <span key={idx} className="neighbor-chip">
                #{nbr}
              </span>
            ))}
          </div>
        </div>

        {/* Vulnerabilities and Patches */}
        <div className="drawer-section">
          <span className="drawer-section-title">HOST VULNERABILITIES ({nodeVulns.length})</span>
          {nodeVulns.length === 0 ? (
            <div className="empty-drawer-vulns">No known findings on this node.</div>
          ) : (
            nodeVulns.map(v => {
              const isPatched = activePatches.includes(v.vulnerability_id);
              return (
                <div key={v.vulnerability_id} className={`drawer-vuln-card ${isPatched ? 'card-patched' : ''}`}>
                  <div className="d-vuln-top">
                    <div>
                      <span className="d-vuln-id">{v.vulnerability_id}</span>
                      <span className="d-vuln-cvss">CVSS {Number(v.cvss).toFixed(1)}</span>
                    </div>
                    {isPatched && <span className="badge-patched-small">PATCHED</span>}
                  </div>

                  <div className="d-vuln-meta">
                    <span>Exploit: {(Number(v.exploit_probability) * 100).toFixed(0)}%</span>
                    <span>Priority: {Number(v.priority_score).toFixed(1)}</span>
                    <span>Patch Value: {Number(v.patch_value || 0).toFixed(3)}</span>
                  </div>

                  <p className="d-vuln-reason">
                    {v.reason || 'Graph-aware priority combines breach probability and shortest path exposure.'}
                  </p>

                  <button
                    className={`drawer-patch-btn ${isPatched ? 'unpatch' : 'patch'}`}
                    onClick={() => onTogglePatch?.(v.vulnerability_id)}
                  >
                    {isPatched ? '✕ Remove Virtual Patch' : '⚡ Simulate Virtual Patch'}
                  </button>
                </div>
              );
            })
          )}
        </div>
      </div>
    </aside>
  );
}
