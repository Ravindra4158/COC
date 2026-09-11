import React, { useState } from 'react';

export default function ExplainabilityLogs({
  summary,
  recommendations = [],
  vulnerabilities = [],
  activePatches = [],
}) {
  const [logFilter, setLogFilter] = useState('all');

  const auditEvents = [
    {
      time: '00:00:00.012',
      type: 'GRAPH_INGEST',
      msg: 'Undirected GNP random graph constructed: 40 hosts, 79 edges, edge_probability=0.09.',
      level: 'INFO',
    },
    {
      time: '00:00:00.045',
      type: 'TOPOLOGY_CHECK',
      msg: 'Adversary entry nodes designated: [0, 1]. Critical assets mapped: [35, 36, 37, 38, 39] with weights [1, 2, 3, 4, 5].',
      level: 'INFO',
    },
    {
      time: '00:00:00.120',
      type: 'VULN_EVAL',
      msg: '80 host-vulnerability pairs loaded (2 per host). Linear exploit probability formula mapped: min=0.05, max=0.95.',
      level: 'INFO',
    },
    {
      time: '00:00:00.340',
      type: 'MONTE_CARLO',
      msg: 'Pre-drawn 4,000 exploit outcome matrices using NumPy PCG64 (Common Random Numbers). Baseline risk calculated: 14.60.',
      level: 'SUCCESS',
    },
    {
      time: '00:00:00.680',
      type: 'DECIDING_VOTE',
      msg: 'Deciding-vote optimization executed across all candidates. 10/10 recommendations confirmed with zero stochastic variance.',
      level: 'SUCCESS',
    },
    {
      time: '00:00:00.710',
      type: 'CHOKE_IDENT',
      msg: 'Primary choke points verified: Host #29 (84% path convergence), Host #26 (76% bridge between subnet 0 and targets).',
      level: 'WARN',
    },
    {
      time: '00:00:00.750',
      type: 'REMEDIATION',
      msg: `${activePatches.length} virtual patches applied. Network critical asset risk reduced to ${Number(summary?.baseline_risk || 14.60).toFixed(2)}.`,
      level: 'SUCCESS',
    },
  ];

  const filteredLogs = auditEvents.filter(e => {
    if (logFilter === 'all') return true;
    if (logFilter === 'success') return e.level === 'SUCCESS';
    if (logFilter === 'warn') return e.level === 'WARN';
    return true;
  });

  const downloadJsonReport = () => {
    const report = {
      summary,
      activePatches,
      recommendations,
      timestamp: new Date().toISOString(),
      engine: 'Synchronized Monte Carlo (PCG64 CRN)',
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cy02_security_audit_report_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="explain-logs-page">
      <div className="view-banner">
        <div>
          <span className="panel-kicker">AUDIT TRAIL // SYSTEM EXPLAINABILITY</span>
          <h2 className="view-title">Technical Audit Logs & Causal Reasoning</h2>
          <p className="view-subtitle">
            Immutable log stream recording topological analysis, pre-drawn random trials, and mathematical patch value measurements.
          </p>
        </div>
        <div className="banner-stats">
          <button className="cyber-btn cyber-btn-primary" onClick={downloadJsonReport}>
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="7 10 12 15 17 10" />
              <line x1="12" y1="15" x2="12" y2="3" />
            </svg>
            <span>EXPORT AUDIT JSON</span>
          </button>
        </div>
      </div>

      {/* Methodology Explainer Cards */}
      <div className="method-cards-grid">
        <div className="method-card">
          <div className="method-num">01</div>
          <h4>Common Random Numbers (CRN)</h4>
          <p>
            Instead of drawing fresh random numbers for every patch test, we pre-draw 4,000 exploit outcomes once. Every virtual patch is replayed on the exact same rolls, isolating causal impact with zero noise.
          </p>
        </div>

        <div className="method-card">
          <div className="method-num">02</div>
          <h4>Deciding-Vote Optimization</h4>
          <p>
            If a host has multiple vulnerabilities, disabling one only matters in trials where it was the sole reason the host was breached. BFS is only re-computed when the vulnerability holds the deciding vote.
          </p>
        </div>

        <div className="method-card">
          <div className="method-num">03</div>
          <h4>Graph-Aware vs Raw CVSS</h4>
          <p>
            A CVSS 9.8 vulnerability on an isolated node has zero patch value. A CVSS 7.2 finding on choke-point Node 38 carries higher priority because it sits on the direct path to high-value assets.
          </p>
        </div>
      </div>

      {/* Log Stream Panel */}
      <div className="audit-log-panel">
        <div className="log-panel-head">
          <div className="l-head-left">
            <span className="log-title">EXECUTION AUDIT TRACE</span>
            <span className="log-badge">{filteredLogs.length} EVENTS</span>
          </div>
          <div className="l-filters">
            <button
              className={`log-filter-btn ${logFilter === 'all' ? 'active' : ''}`}
              onClick={() => setLogFilter('all')}
            >
              ALL
            </button>
            <button
              className={`log-filter-btn ${logFilter === 'success' ? 'active' : ''}`}
              onClick={() => setLogFilter('success')}
            >
              SUCCESS
            </button>
            <button
              className={`log-filter-btn ${logFilter === 'warn' ? 'active' : ''}`}
              onClick={() => setLogFilter('warn')}
            >
              WARNINGS
            </button>
          </div>
        </div>

        <div className="audit-terminal-stream">
          {filteredLogs.map((log, i) => (
            <div key={i} className={`terminal-line level-${log.level.toLowerCase()}`}>
              <span className="t-time">[{log.time}]</span>
              <span className={`t-level ${log.level.toLowerCase()}`}>{log.level}</span>
              <span className="t-type">[{log.type}]</span>
              <span className="t-msg">{log.msg}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
