import React, { useState, useEffect } from 'react';

const getTodayVal = () => {
  const now = new Date();
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, '0');
  const d = String(now.getDate()).padStart(2, '0');
  return parseInt(`${y}${m}${d}`, 10);
};

export default function TopNavbar({
  running,
  onRunSimulation,
  activeSeed,
  onChangeSeed,
  activePatches,
  onResetState,
}) {
  const [utcTime, setUtcTime] = useState('');
  const todayVal = getTodayVal();
  const [customInput, setCustomInput] = useState('');
  const [showCustom, setShowCustom] = useState(false);

  const SEED_OPTIONS = [
    { val: 20260911, label: 'Dev Instance (20260911)' },
    { val: todayVal, label: `Today's Date (${todayVal})` },
    { val: 42, label: 'Evaluator Seed (42)' },
    { val: 1337, label: 'Adversarial Seed (1337)' },
  ];

  useEffect(() => {
    const update = () => {
      const now = new Date();
      setUtcTime(now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC');
    };
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleCustomSubmit = (e) => {
    e.preventDefault();
    if (customInput.trim()) {
      onChangeSeed(customInput.trim());
      setShowCustom(false);
    }
  };

  return (
    <header className="cyber-topbar">
      {/* Left: System Identification */}
      <div className="topbar-left">
        <div className="system-tag">
          <span className="system-dot" />
          <span className="system-name">CYBERGRAPH // CY-02 SENTINEL</span>
          <span className="system-env">PROD // ENCLAVE-ALPHA</span>
        </div>
        <div className="live-clock">
          <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10" />
            <polyline points="12 6 12 12 16 14" />
          </svg>
          <span>{utcTime}</span>
        </div>
      </div>

      {/* Center: Live Status Indicator */}
      <div className="topbar-center">
        <div className={`status-pill ${running ? 'running' : 'completed'}`}>
          <span className="pulse-indicator" />
          <span className="status-text">
            {running ? 'MONTE CARLO SIMULATION IN PROGRESS...' : 'SYSTEM READY // 4,000 SYNCHRONIZED TRIALS'}
          </span>
        </div>
      </div>

      {/* Right: Controls & User Profile */}
      <div className="topbar-right">
        {/* Seed Selector */}
        <div className="seed-control-group">
          <label className="control-label">TOPOLOGY</label>
          {!showCustom ? (
            <select
              className="cyber-select"
              value={activeSeed || 20260911}
              onChange={e => {
                if (e.target.value === 'custom') {
                  setShowCustom(true);
                } else {
                  onChangeSeed(Number(e.target.value));
                }
              }}
              disabled={running}
            >
              {SEED_OPTIONS.map(opt => (
                <option key={opt.val} value={opt.val}>
                  {opt.label}
                </option>
              ))}
              <option value="custom">Custom Seed / Date...</option>
            </select>
          ) : (
            <form onSubmit={handleCustomSubmit} style={{ display: 'flex', gap: '4px', alignItems: 'center' }}>
              <input
                type="text"
                className="cyber-select"
                style={{ width: '130px', padding: '2px 8px' }}
                placeholder="e.g. 2026-09-12 or 99"
                value={customInput}
                onChange={e => setCustomInput(e.target.value)}
                autoFocus
              />
              <button type="submit" className="cyber-btn cyber-btn-ghost" style={{ padding: '4px 8px' }}>
                SET
              </button>
              <button
                type="button"
                className="cyber-btn cyber-btn-ghost"
                style={{ padding: '4px 8px' }}
                onClick={() => setShowCustom(false)}
              >
                ✕
              </button>
            </form>
          )}
        </div>

        {/* Quick Today's Date Button */}
        <button
          className="cyber-btn cyber-btn-ghost"
          onClick={() => onChangeSeed(todayVal)}
          disabled={running}
          title={`Switch directly to today's date seed (${todayVal})`}
        >
          TODAY
        </button>

        {/* Reset State if active patches or custom seed */}
        {(activePatches?.length > 0 || (activeSeed && activeSeed !== 20260911)) && (
          <button
            className="cyber-btn cyber-btn-ghost"
            onClick={onResetState}
            disabled={running}
            title="Reset patches & restore default baseline"
          >
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
              <path d="M3 3v5h5" />
            </svg>
            <span>RESET ({activePatches.length})</span>
          </button>
        )}

        {/* Run Simulation Button */}
        <button
          className={`cyber-btn cyber-btn-primary ${running ? 'loading' : ''}`}
          onClick={onRunSimulation}
          disabled={running}
        >
          {running ? (
            <>
              <span className="btn-spinner" />
              <span>SIMULATING...</span>
            </>
          ) : (
            <>
              <svg viewBox="0 0 24 24" width="15" height="15" fill="currentColor">
                <path d="M8 5v14l11-7z" />
              </svg>
              <span>RUN SIMULATION</span>
            </>
          )}
        </button>

        {/* User Profile */}
        <div className="user-profile-card">
          <div className="user-avatar">
            <span>SO</span>
          </div>
          <div className="user-meta">
            <span className="user-name">SecOps Lead</span>
            <span className="user-role">DEF-SPEC // LVL-4</span>
          </div>
        </div>
      </div>
    </header>
  );
}
