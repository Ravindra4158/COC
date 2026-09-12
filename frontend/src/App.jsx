import React, { useCallback, useEffect, useState } from 'react';
import Sidebar from './components/Sidebar';
import TopNavbar from './components/TopNavbar';
import KeyMetrics from './components/KeyMetrics';
import NetworkGraph from './components/NetworkGraph';
import AttackSimulationPanel from './components/AttackSimulationPanel';
import VulnerabilityRankingTable from './components/VulnerabilityRankingTable';
import PatchImpactVisualization from './components/PatchImpactVisualization';
import ExplainabilityPanel from './components/ExplainabilityPanel';
import NodeDetailDrawer from './components/NodeDetailDrawer';
import PatchImpactView from './components/PatchImpactView';
import ExplainabilityLogs from './components/ExplainabilityLogs';
import LoadingState from './components/LoadingState';
import SplashLanding from './components/SplashLanding';

import {
  getAnalysis,
  getNetwork,
  getRecommendations,
  getVulnerabilities,
  runAnalysis,
  resetAnalysis,
} from './services/api';

export default function App() {
  const [showSplash, setShowSplash] = useState(true);
  const [currentTab, setCurrentTab] = useState('dashboard');
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');

  // Active state
  const [activePatches, setActivePatches] = useState([]);
  const [activeSeed, setActiveSeed] = useState(20260911);
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [simulationState, setSimulationState] = useState(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [summary, network, vulnerabilities, recommendations] = await Promise.all([
        getAnalysis(),
        getNetwork(),
        getVulnerabilities(),
        getRecommendations(),
      ]);
      setData({
        summary,
        network,
        vulnerabilities: vulnerabilities.items || [],
        recommendations: recommendations.items || [],
      });
      if (summary.active_patches) setActivePatches(summary.active_patches);
      if (summary.active_seed) setActiveSeed(summary.active_seed);
    } catch {
      setError('Unable to connect to analysis backend. Run: .venv/bin/uvicorn app.main:app --reload');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Run or refresh simulation
  const handleRunSimulation = async () => {
    setRunning(true);
    setError('');
    try {
      await runAnalysis({ disabled_vulnerabilities: activePatches, seed: activeSeed });
      await loadData();
    } catch {
      setError('Simulation run failed. Check backend terminal logs.');
    } finally {
      setRunning(false);
    }
  };

  // Toggle virtual patch
  const handleTogglePatch = async (vulnId) => {
    setRunning(true);
    setError('');
    try {
      const next = activePatches.includes(vulnId)
        ? activePatches.filter(id => id !== vulnId)
        : [...activePatches, vulnId];
      setActivePatches(next);
      await runAnalysis({ disabled_vulnerabilities: next, seed: activeSeed });
      await loadData();
    } catch {
      setError('Virtual patch update failed. Check backend logs.');
    } finally {
      setRunning(false);
    }
  };

  // Change topology seed
  const handleChangeSeed = async (seed) => {
    setRunning(true);
    setError('');
    try {
      setActiveSeed(seed);
      await runAnalysis({ disabled_vulnerabilities: activePatches, seed });
      await loadData();
    } catch {
      setError('Failed to switch network seed.');
    } finally {
      setRunning(false);
    }
  };

  // Reset state to default
  const handleResetState = async () => {
    setRunning(true);
    setError('');
    try {
      await resetAnalysis();
      setActivePatches([]);
      setActiveSeed(20260911);
      await loadData();
    } catch {
      setError('Failed to reset state.');
    } finally {
      setRunning(false);
    }
  };

  // Render current tab content
  const renderContent = () => {
    if (loading) return <LoadingState />;
    if (!data) return null;

    switch (currentTab) {
      case 'dashboard':
        return (
          <div className="dashboard-flow">
            {/* Section 1: Key Metrics */}
            <KeyMetrics
              summary={data.summary}
              recommendations={data.recommendations}
              activePatches={activePatches}
            />

            {/* Sections 2 & 3: Network Graph & Attack Propagation split */}
            <div className="dashboard-two-col">
              <div className="col-graph">
                <NetworkGraph
                  network={data.network}
                  vulnerabilities={data.vulnerabilities}
                  selectedNode={selectedNode}
                  onSelectNode={setSelectedNode}
                  activePatches={activePatches}
                  onTogglePatch={handleTogglePatch}
                  simulationState={simulationState}
                />
              </div>

              <div className="col-simulation">
                <AttackSimulationPanel
                  network={data.network}
                  vulnerabilities={data.vulnerabilities}
                  activePatches={activePatches}
                  onUpdateSimulationState={setSimulationState}
                />
              </div>
            </div>

            {/* Section 4: Vulnerability Ranking Table (Top 10 in Dashboard) */}
            <div className="dashboard-full-row">
              <VulnerabilityRankingTable
                items={data.vulnerabilities}
                selectedItem={selectedFinding}
                onSelect={setSelectedFinding}
                activePatches={activePatches}
                onTogglePatch={handleTogglePatch}
                limit={10}
                onViewAll={() => setCurrentTab('ranking')}
              />
            </div>

            {/* Sections 5 & 6: Patch Impact Bar Chart & Explainability Witness split */}
            <div className="dashboard-two-col-equal">
              <div className="col-impact">
                <PatchImpactVisualization
                  summary={data.summary}
                  recommendations={data.recommendations}
                  activePatches={activePatches}
                />
              </div>

              <div className="col-explain">
                <ExplainabilityPanel
                  recommendations={data.recommendations}
                  selectedFinding={selectedFinding}
                  onSelectFinding={setSelectedFinding}
                />
              </div>
            </div>
          </div>
        );

      case 'network':
        return (
          <div className="tab-standalone-page">
            <NetworkGraph
              network={data.network}
              vulnerabilities={data.vulnerabilities}
              selectedNode={selectedNode}
              onSelectNode={setSelectedNode}
              activePatches={activePatches}
              onTogglePatch={handleTogglePatch}
              simulationState={simulationState}
            />
          </div>
        );

      case 'simulation':
        return (
          <div className="tab-standalone-page">
            <div className="dashboard-two-col simulation-full-page">
              <div className="col-graph">
                <NetworkGraph
                  network={data.network}
                  vulnerabilities={data.vulnerabilities}
                  selectedNode={selectedNode}
                  onSelectNode={setSelectedNode}
                  activePatches={activePatches}
                  onTogglePatch={handleTogglePatch}
                  simulationState={simulationState}
                />
              </div>
              <div className="col-simulation">
                <AttackSimulationPanel
                  network={data.network}
                  vulnerabilities={data.vulnerabilities}
                  activePatches={activePatches}
                  onUpdateSimulationState={setSimulationState}
                />
              </div>
            </div>
          </div>
        );

      case 'ranking':
        return (
          <div className="tab-standalone-page">
            <VulnerabilityRankingTable
              items={data.vulnerabilities}
              selectedItem={selectedFinding}
              onSelect={setSelectedFinding}
              activePatches={activePatches}
              onTogglePatch={handleTogglePatch}
              limit={10}
            />
          </div>
        );

      case 'patches':
        return (
          <div className="tab-standalone-page">
            <PatchImpactView
              recommendations={data.recommendations}
              activePatches={activePatches}
              onTogglePatch={handleTogglePatch}
              onSelectFinding={setSelectedFinding}
              summary={data.summary}
            />
          </div>
        );

      case 'logs':
        return (
          <div className="tab-standalone-page">
            <ExplainabilityLogs
              summary={data.summary}
              recommendations={data.recommendations}
              vulnerabilities={data.vulnerabilities}
              activePatches={activePatches}
            />
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <>
      {showSplash && <SplashLanding onComplete={() => setShowSplash(false)} />}
      <div className="cyber-app-shell">
        {/* Left Sidebar */}
        <Sidebar
          currentTab={currentTab}
          setTab={setCurrentTab}
          activePatchesCount={activePatches.length}
        />

        {/* Main Operations Area */}
        <div className="cyber-main-viewport">
          {/* Top Navbar */}
          <TopNavbar
            running={running}
            onRunSimulation={handleRunSimulation}
            activeSeed={activeSeed}
            onChangeSeed={handleChangeSeed}
            activePatches={activePatches}
            onResetState={handleResetState}
          />

          {/* Global Error Banner */}
          {error && (
            <div className="cyber-error-banner">
              <div className="error-content">
                <span className="error-icon">⚠️</span>
                <span className="error-text">{error}</span>
              </div>
              <button className="error-retry-btn" onClick={loadData}>
                RETRY
              </button>
            </div>
          )}

          {/* Dynamic View Content */}
          <main className="cyber-content-container">{renderContent()}</main>

          {/* Side Drawer when a node is selected */}
          {selectedNode && (
            <NodeDetailDrawer
              node={selectedNode}
              vulnerabilities={data?.vulnerabilities || []}
              network={data?.network}
              activePatches={activePatches}
              onTogglePatch={handleTogglePatch}
              onClose={() => setSelectedNode(null)}
            />
          )}
        </div>
      </div>
    </>
  );
}
