import React, { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';

export default function NetworkGraph({
  network,
  vulnerabilities = [],
  selectedNode,
  onSelectNode,
  activePatches = [],
  onTogglePatch,
  simulationState = null,
}) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const [filterHighRiskOnly, setFilterHighRiskOnly] = useState(false);
  const [showPatchedOverlay, setShowPatchedOverlay] = useState(true);

  // Helper to map node risk level (Green / Yellow / Red)
  const getNodeRiskColor = (nodeId) => {
    const idNum = Number(nodeId);
    if ([35, 36, 37, 38, 39].includes(idNum)) return '#ef4444'; // Red: Critical Asset
    if ([0, 1].includes(idNum)) return '#10b981'; // Green: Entry points
    
    // Check vulnerabilities for this host
    const nodeVulns = vulnerabilities.filter(v => String(v.host_id) === String(nodeId));
    if (!nodeVulns.length) return '#10b981';

    // If all findings on this host are patched, render cyber green!
    const unpatched = nodeVulns.filter(v => !activePatches.includes(v.vulnerability_id));
    if (showPatchedOverlay && unpatched.length === 0) return '#059669';
    
    const maxCvss = Math.max(...unpatched.map(v => Number(v.cvss || 0)), 0);
    const maxPrio = Math.max(...unpatched.map(v => Number(v.priority_score || 0)), 0);
    
    if (maxPrio >= 70 || maxCvss >= 8.5) return '#f43f5e'; // Red: High risk
    if (maxPrio >= 50 || maxCvss >= 6.5) return '#f59e0b'; // Yellow/Amber: Medium
    return '#10b981'; // Green: Low
  };

  useEffect(() => {
    if (!containerRef.current || !network?.nodes) return;

    const elements = [
      ...network.nodes.map(node => {
        const idNum = Number(node.id);
        const isEntry = [0, 1].includes(idNum);
        const isCritical = [35, 36, 37, 38, 39].includes(idNum);
        const color = getNodeRiskColor(node.id);
        
        return {
          data: {
            ...node,
            id: String(node.id),
            label: String(node.id),
            isEntry,
            isCritical,
            riskColor: color,
          },
        };
      }),
      ...network.edges.map((edge, i) => ({
        data: {
          id: `e-${i}`,
          source: String(edge.source),
          target: String(edge.target),
        },
      })),
    ];

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      layout: {
        name: 'cose',
        animate: false,
        padding: 30,
        nodeRepulsion: () => 450000,
        idealEdgeLength: () => 65,
        edgeElasticity: () => 100,
        nestingFactor: 1.2,
      },
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(riskColor)',
            label: 'data(label)',
            color: '#f8fafc',
            'font-family': 'JetBrains Mono, monospace',
            'font-size': '10px',
            'font-weight': 600,
            'text-valign': 'center',
            'text-halign': 'center',
            width: 28,
            height: 28,
            'border-width': 1.5,
            'border-color': '#334155',
            'transition-property': 'background-color, border-color, width, height, border-width, opacity',
            'transition-duration': '0.2s',
          },
        },
        {
          selector: 'node[?isEntry]',
          style: {
            'background-color': '#064e3b',
            'border-color': '#10b981',
            'border-width': 3.5,
            width: 32,
            height: 32,
            color: '#34d399',
          },
        },
        {
          selector: 'node[?isCritical]',
          style: {
            'background-color': '#7f1d1d',
            'border-color': '#f43f5e',
            'border-width': 3.5,
            width: 36,
            height: 36,
            color: '#fca5a5',
            'font-size': '11px',
            'font-weight': 700,
          },
        },
        {
          selector: 'edge',
          style: {
            width: 1.5,
            'line-color': '#1e293b',
            'curve-style': 'straight',
            opacity: 0.7,
            'transition-property': 'line-color, width, opacity',
            'transition-duration': '0.2s',
          },
        },
        {
          selector: ':selected',
          style: {
            'border-color': '#00f0ff',
            'border-width': 4,
            'shadow-blur': 14,
            'shadow-color': '#00f0ff',
            'shadow-opacity': 0.9,
          },
        },
      ],
      userZoomingEnabled: true,
      userPanningEnabled: true,
      boxSelectionEnabled: false,
    });

    cy.on('tap', 'node', evt => {
      const d = evt.target.data();
      onSelectNode?.(d);
    });

    cy.on('mouseover', 'node', evt => {
      const d = evt.target.data();
      const renderedPos = evt.renderedPosition;
      setHoveredNode(d);
      setTooltipPos({ x: renderedPos.x, y: renderedPos.y });
    });

    cy.on('mouseout', 'node', () => {
      setHoveredNode(null);
    });

    cyRef.current = cy;
    return () => cy.destroy();
  }, [network, showPatchedOverlay, activePatches]);

  // Handle High-risk only filter toggle
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.batch(() => {
      cy.nodes().forEach(node => {
        const id = node.id();
        const color = getNodeRiskColor(id);
        const isEntry = [0, 1].includes(Number(id));
        const isCritical = [35, 36, 37, 38, 39].includes(Number(id));
        const isHigh = color === '#ef4444' || color === '#f43f5e';

        if (filterHighRiskOnly) {
          if (isHigh || isEntry || isCritical) {
            node.style({ opacity: 1 });
          } else {
            node.style({ opacity: 0.15 });
          }
        } else {
          node.style({ opacity: 1 });
        }
      });
    });
  }, [filterHighRiskOnly]);

  // Update styles if attack propagation animation is running
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.batch(() => {
      if (simulationState) {
        const { compromised = [], frontier = [] } = simulationState;
        cy.nodes().forEach(node => {
          const id = Number(node.id());
          if (compromised.includes(id)) {
            node.style({
              'background-color': '#ef4444',
              'border-color': '#fca5a5',
              'border-width': 3,
            });
          } else if (frontier.includes(id)) {
            node.style({
              'background-color': '#f59e0b',
              'border-color': '#fde68a',
              'border-width': 3,
            });
          } else {
            node.style({
              'background-color': '#1e293b',
              'border-color': '#334155',
              'border-width': 1,
            });
          }
        });

        cy.edges().forEach(edge => {
          const src = Number(edge.data('source'));
          const tgt = Number(edge.data('target'));
          if (compromised.includes(src) && compromised.includes(tgt)) {
            edge.style({ 'line-color': '#ef4444', width: 2.5, opacity: 0.9 });
          } else if (
            (compromised.includes(src) && frontier.includes(tgt)) ||
            (compromised.includes(tgt) && frontier.includes(src))
          ) {
            edge.style({ 'line-color': '#f59e0b', width: 2, opacity: 0.8 });
          } else {
            edge.style({ 'line-color': '#1e293b', width: 1, opacity: 0.4 });
          }
        });
      }
    });
  }, [simulationState]);

  // Tooltip details for currently hovered node
  const hoveredVulns = hoveredNode
    ? vulnerabilities.filter(v => String(v.host_id) === String(hoveredNode.id))
    : [];
  const hoveredCvss = hoveredVulns.map(v => Number(v.cvss || 0).toFixed(1)).join(', ');
  const hoveredExploit = hoveredVulns
    .map(v => `${(Number(v.exploit_probability || 0) * 100).toFixed(0)}%`)
    .join(', ');

  const fitGraph = () => cyRef.current?.fit(null, 30);
  const resetZoom = () => cyRef.current?.reset();

  return (
    <div className="network-graph-container">
      {/* Graph Toolbar */}
      <div className="graph-toolbar">
        <div className="toolbar-left">
          <span className="panel-kicker">SECTION 2 // TOPOLOGY & ATTACK SURFACE</span>
          <h3 className="panel-title">Interactive Network Topology Graph</h3>
        </div>

        <div className="toolbar-right">
          {/* Toggles */}
          <div className="graph-toggles-row">
            <button
              className={`toggle-pill ${filterHighRiskOnly ? 'active' : ''}`}
              onClick={() => setFilterHighRiskOnly(!filterHighRiskOnly)}
            >
              <span className="toggle-bullet" />
              <span>High-Risk Only</span>
            </button>

            <button
              className={`toggle-pill ${showPatchedOverlay ? 'active' : ''}`}
              onClick={() => setShowPatchedOverlay(!showPatchedOverlay)}
            >
              <span className="toggle-bullet" />
              <span>{showPatchedOverlay ? 'Patched Overlay' : 'Raw Network'}</span>
            </button>
          </div>

          <div className="graph-legend">
            <span className="legend-chip">
              <span className="dot dot-entry" /> Entry (0, 1)
            </span>
            <span className="legend-chip">
              <span className="dot dot-red" /> High Risk (35–39)
            </span>
            <span className="legend-chip">
              <span className="dot dot-yellow" /> Medium
            </span>
            <span className="legend-chip">
              <span className="dot dot-green" /> Low
            </span>
          </div>

          <div className="btn-group">
            <button className="tool-btn" onClick={fitGraph} title="Fit to screen">
              FIT
            </button>
            <button className="tool-btn" onClick={resetZoom} title="Reset view">
              RESET
            </button>
          </div>
        </div>
      </div>

      {/* Main Canvas with Floating Tooltip */}
      <div className="graph-canvas-relative">
        <div className="graph-canvas-wrapper" ref={containerRef} />

        {/* Hover Tooltip */}
        {hoveredNode && (
          <div
            className="cy-floating-tooltip"
            style={{
              left: `${Math.min(window.innerWidth - 300, tooltipPos.x + 15)}px`,
              top: `${Math.max(10, tooltipPos.y - 40)}px`,
            }}
          >
            <div className="tt-header">
              <span className="tt-id">HOST #{hoveredNode.id}</span>
              {hoveredNode.isEntry && <span className="tt-tag tag-entry">ENTRY NODE</span>}
              {hoveredNode.isCritical && <span className="tt-tag tag-crit">CRITICAL ASSET</span>}
            </div>
            <div className="tt-row">
              <span className="tt-label">CVSS Scores:</span>
              <span className="tt-val text-amber">{hoveredCvss || 'None'}</span>
            </div>
            <div className="tt-row">
              <span className="tt-label">Exploit Probabilities:</span>
              <span className="tt-val text-cyan">{hoveredExploit || 'None'}</span>
            </div>
            <div className="tt-hint">Click node to inspect details & patch findings</div>
          </div>
        )}
      </div>
    </div>
  );
}
