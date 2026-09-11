import React from 'react';

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: 'M3 3h7v7H3V3zm11 0h7v7h-7V3zm0 11h7v7h-7v-7zM3 14h7v7H3v-7z', badge: 'LIVE' },
  { id: 'network', label: 'Network Graph', icon: 'M12 2a3 3 0 0 0-3 3c0 .3.05.59.13.86L5.86 8.13A3 3 0 0 0 5 8a3 3 0 1 0 2.87 3.87l3.26 3.26c-.08.27-.13.56-.13.87a3 3 0 1 0 3-3c-.3 0-.59.05-.86-.13l-3.27-3.27c.08-.27.13-.56.13-.87 0-.31-.05-.6-.13-.87l3.27-3.27c.27.08.56.13.86.13a3 3 0 1 0-3-3z', count: '40' },
  { id: 'simulation', label: 'Attack Simulation', icon: 'M13 2L3 14h9l-1 8 10-12h-9l1-8z', badge: 'ACTIVE' },
  { id: 'ranking', label: 'Vulnerability Ranking', icon: 'M3 4h18v2H3V4zm0 7h12v2H3v-2zm0 7h18v2H3v-2z', count: '80' },
  { id: 'patches', label: 'Patch Impact', icon: 'M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z', count: '10' },
  { id: 'logs', label: 'Logs / Explainability', icon: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z', badge: 'AUDIT' },
];

export default function Sidebar({ currentTab, setTab, activePatchesCount = 0 }) {
  return (
    <aside className="cyber-sidebar">
      {/* Brand Header */}
      <div className="cyber-brand">
        <div className="brand-shield">
          <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <path d="M9 12l2 2 4-4" stroke="var(--cyber-accent)" strokeWidth="2.5" />
          </svg>
        </div>
        <div className="brand-text">
          <span className="brand-title">CYBERGRAPH</span>
          <span className="brand-sub">CY-02 SENTINEL // v2.4</span>
        </div>
      </div>

      {/* Clearance indicator */}
      <div className="clearance-banner">
        <span className="clearance-indicator" />
        <span className="clearance-text">CLEARANCE: TS // ENTERPRISE DEFENSE</span>
      </div>

      {/* Nav List */}
      <nav className="cyber-nav">
        <span className="nav-section-label">OPERATIONS</span>
        {NAV_ITEMS.map(item => {
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              className={`cyber-nav-item ${isActive ? 'active' : ''}`}
              onClick={() => setTab(item.id)}
            >
              <svg className="nav-icon" viewBox="0 0 24 24" width="18" height="18" fill="currentColor">
                <path d={item.icon} />
              </svg>
              <span className="nav-label">{item.label}</span>
              {item.badge && <span className={`nav-badge ${item.badge.toLowerCase()}`}>{item.badge}</span>}
              {item.count && <span className="nav-count">{item.count}</span>}
            </button>
          );
        })}
      </nav>

      {/* System Status Footer */}
      <div className="cyber-sidebar-footer">
        <div className="footer-status-row">
          <span className="status-label">GRAPH ENGINE</span>
          <span className="status-val text-emerald">SYNCHRONIZED CRN</span>
        </div>
        <div className="footer-status-row">
          <span className="status-label">ACTIVE PATCHES</span>
          <span className={`status-val ${activePatchesCount > 0 ? 'text-cyan font-bold' : 'text-slate'}`}>
            {activePatchesCount} APPLIED
          </span>
        </div>
        <div className="footer-status-row">
          <span className="status-label">BUDGET BOUND</span>
          <span className="status-val">4,000 SIMS</span>
        </div>
      </div>
    </aside>
  );
}
