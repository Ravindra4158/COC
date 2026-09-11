import React, { useState, useEffect, useRef } from 'react';

export default function AttackSimulationPanel({
  network,
  vulnerabilities = [],
  activePatches = [],
  onUpdateSimulationState, // callback to highlight nodes in NetworkGraph
}) {
  const [isPlaying, setIsPlaying] = useState(false);
  const [step, setStep] = useState(0);
  const [speedMs, setSpeedMs] = useState(1000);
  const [compromised, setCompromised] = useState([0, 1]); // starts at entry nodes 0, 1
  const [frontier, setFrontier] = useState([]);
  const [history, setHistory] = useState([]);
  const [breachedTargets, setBreachedTargets] = useState([]);

  const CRITICAL_TARGETS = [35, 36, 37, 38, 39];

  // Adjacency mapping from network edges
  const adjMap = useRef(new Map());
  useEffect(() => {
    const map = new Map();
    if (network?.nodes) {
      network.nodes.forEach(n => map.set(Number(n.id), []));
    }
    if (network?.edges) {
      network.edges.forEach(e => {
        const u = Number(e.source);
        const v = Number(e.target);
        if (!map.has(u)) map.set(u, []);
        if (!map.has(v)) map.set(v, []);
        map.get(u).push(v);
        map.get(v).push(u);
      });
    }
    adjMap.current = map;
    resetSimulation();
  }, [network, activePatches]);

  // Notify parent of state changes for graph visualization
  useEffect(() => {
    onUpdateSimulationState?.({
      compromised,
      frontier,
      step,
    });
  }, [compromised, frontier, step]);

  const resetSimulation = () => {
    setIsPlaying(false);
    setStep(0);
    const initialCompromised = [0, 1];
    setCompromised(initialCompromised);

    // Initial frontier = uncompromised neighbors of entry nodes
    const map = adjMap.current;
    const initialFrontier = new Set();
    initialCompromised.forEach(entry => {
      (map.get(entry) || []).forEach(nbr => {
        if (!initialCompromised.includes(nbr)) {
          initialFrontier.add(nbr);
        }
      });
    });

    const frontArr = Array.from(initialFrontier);
    setFrontier(frontArr);
    setHistory([
      {
        step: 0,
        text: 'Attacker initialized at entry nodes [0, 1]. Establishing initial foothold.',
        newlyBreached: [0, 1],
      },
    ]);
    setBreachedTargets([]);
  };

  const advanceStep = () => {
    if (frontier.length === 0) {
      setIsPlaying(false);
      return;
    }

    const currentCompromisedSet = new Set(compromised);
    const newlyBreached = [];
    const blockedNodes = [];

    // Test each frontier node
    frontier.forEach(nodeId => {
      // Check vulnerabilities on this node
      const nodeVulns = vulnerabilities.filter(v => Number(v.host_id) === Number(nodeId));
      const unpatched = nodeVulns.filter(v => !activePatches.includes(v.vulnerability_id));

      if (unpatched.length === 0) {
        // Node is fully patched! Attack blocked
        blockedNodes.push(nodeId);
      } else {
        // Node is exploitable
        newlyBreached.push(nodeId);
        currentCompromisedSet.add(nodeId);
      }
    });

    const updatedCompromised = Array.from(currentCompromisedSet);

    // Calculate new frontier: uncompromised neighbors of all compromised nodes
    const map = adjMap.current;
    const nextFrontierSet = new Set();
    updatedCompromised.forEach(comp => {
      (map.get(comp) || []).forEach(nbr => {
        if (!currentCompromisedSet.has(nbr)) {
          nextFrontierSet.add(nbr);
        }
      });
    });

    const nextFrontier = Array.from(nextFrontierSet);
    const currentBreachedTargets = updatedCompromised.filter(id => CRITICAL_TARGETS.includes(id));

    setCompromised(updatedCompromised);
    setFrontier(nextFrontier);
    setBreachedTargets(currentBreachedTargets);
    setStep(prev => prev + 1);

    // Record history log entry
    let logMsg = `Step ${step + 1}: Breached ${newlyBreached.length} node(s) [${newlyBreached.join(', ') || 'none'}].`;
    if (blockedNodes.length > 0) {
      logMsg += ` Blocked by virtual patch at node(s) [${blockedNodes.join(', ')}].`;
    }
    if (currentBreachedTargets.length > 0) {
      logMsg += ` Critical assets compromised: [${currentBreachedTargets.join(', ')}].`;
    }

    setHistory(prev => [
      {
        step: step + 1,
        text: logMsg,
        newlyBreached,
        blockedNodes,
      },
      ...prev,
    ]);

    // Check completion condition
    if (nextFrontier.length === 0 || currentBreachedTargets.length === CRITICAL_TARGETS.length) {
      setIsPlaying(false);
    }
  };

  // Timer loop when isPlaying is true
  useEffect(() => {
    let timer = null;
    if (isPlaying) {
      timer = setTimeout(() => {
        advanceStep();
      }, speedMs);
    }
    return () => clearTimeout(timer);
  }, [isPlaying, step, frontier, speedMs]);

  return (
    <div className="simulation-panel">
      {/* Simulation Header */}
      <div className="simulation-header">
        <div className="sim-title-group">
          <span className="panel-kicker">SECTION 3 // ATTACK PROPAGATION ENGINE</span>
          <h3 className="panel-title">BFS Attack Path Simulation</h3>
        </div>
        <div className="sim-controls">
          <button
            className={`sim-btn ${isPlaying ? 'sim-btn-pause' : 'sim-btn-play'}`}
            onClick={() => setIsPlaying(!isPlaying)}
          >
            {isPlaying ? (
              <>
                <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor">
                  <path d="M6 4h4v16H6V4zm8 0h4v16h-4V4z" />
                </svg>
                <span>PAUSE</span>
              </>
            ) : (
              <>
                <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor">
                  <path d="M8 5v14l11-7z" />
                </svg>
                <span>PLAY SIMULATION</span>
              </>
            )}
          </button>
          <button
            className="sim-btn sim-btn-ghost"
            onClick={advanceStep}
            disabled={isPlaying || frontier.length === 0}
            title="Step forward 1 hop"
          >
            STEP +1
          </button>
          <button className="sim-btn sim-btn-ghost" onClick={resetSimulation} title="Reset to step 0">
            RESET
          </button>
          <div className="speed-group">
            <button
              className={`speed-pill ${speedMs === 1500 ? 'active' : ''}`}
              onClick={() => setSpeedMs(1500)}
            >
              0.5x
            </button>
            <button
              className={`speed-pill ${speedMs === 1000 ? 'active' : ''}`}
              onClick={() => setSpeedMs(1000)}
            >
              1.0x
            </button>
            <button
              className={`speed-pill ${speedMs === 400 ? 'active' : ''}`}
              onClick={() => setSpeedMs(400)}
            >
              2.5x
            </button>
          </div>
        </div>
      </div>

      {/* Simulation Realtime Status Row */}
      <div className="sim-stats-bar">
        <div className="sim-stat">
          <span className="stat-label">PROPAGATION STEP</span>
          <span className="stat-val text-cyan">STEP {step}</span>
        </div>
        <div className="sim-stat">
          <span className="stat-label">COMPROMISED HOSTS</span>
          <span className="stat-val text-rose">{compromised.length} / 40 ({((compromised.length / 40) * 100).toFixed(0)}%)</span>
        </div>
        <div className="sim-stat">
          <span className="stat-label">ACTIVE FRONTIER</span>
          <span className="stat-val text-amber">{frontier.length} HOSTS</span>
        </div>
        <div className="sim-stat">
          <span className="stat-label">CRITICAL ASSETS BREACHED</span>
          <span className={`stat-val ${breachedTargets.length > 0 ? 'text-rose font-bold' : 'text-emerald'}`}>
            {breachedTargets.length} / 5
          </span>
        </div>
        <div className="sim-stat">
          <span className="stat-label">ACTIVE PATCHES</span>
          <span className="stat-val text-emerald">{activePatches.length} VIRTUAL</span>
        </div>
      </div>

      {/* Frontier and Compromised node badges */}
      <div className="sim-nodes-breakdown">
        <div className="breakdown-group">
          <div className="group-label">
            <span className="badge-dot dot-amber" />
            <span>FRONTIER NODES (NEXT TARGETS):</span>
          </div>
          <div className="node-chips-container">
            {frontier.length === 0 ? (
              <span className="no-nodes">No active frontier (propagation halted or network fully penetrated).</span>
            ) : (
              frontier.map(id => (
                <span key={id} className="chip chip-frontier">
                  Host #{id}
                  {CRITICAL_TARGETS.includes(id) && <b className="chip-crit">CRIT</b>}
                </span>
              ))
            )}
          </div>
        </div>

        <div className="breakdown-group">
          <div className="group-label">
            <span className="badge-dot dot-rose" />
            <span>COMPROMISED NODES ({compromised.length}):</span>
          </div>
          <div className="node-chips-container">
            {compromised.map(id => (
              <span key={id} className={`chip ${CRITICAL_TARGETS.includes(id) ? 'chip-compromised-target' : 'chip-compromised'}`}>
                #{id}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Live Simulation Step Logs */}
      <div className="sim-log-viewer">
        <div className="log-header">
          <span>EVENT LOG TRACE</span>
          <span className="log-count">{history.length} STEPS LOGGED</span>
        </div>
        <div className="log-stream">
          {history.map((h, i) => (
            <div key={i} className={`log-entry ${h.step === step ? 'latest' : ''}`}>
              <span className="log-step">[{String(h.step).padStart(2, '0')}]</span>
              <span className="log-text">{h.text}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
