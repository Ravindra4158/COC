import { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';

export default function NetworkGraph({ network, onSelect }) {
  const containerRef = useRef(null);
  useEffect(() => {
    if (!containerRef.current || !network) return undefined;
    const cy = cytoscape({ container: containerRef.current, elements: [...network.nodes.map(node => ({ data: node })), ...network.edges.map((edge, index) => ({ data: { id: `edge-${index}`, ...edge } }))], layout: { name: 'cose', animate: false, padding: 30, idealEdgeLength: 100 }, style: [
      { selector: 'node', style: { 'background-color': '#406b63', label: 'data(label)', color: '#eaf0e9', 'font-size': 10, 'text-valign': 'bottom', 'text-margin-y': 8, width: 28, height: 28, 'border-width': 2, 'border-color': '#8aa99a' } },
      { selector: 'node[is_critical = "true"]', style: { 'background-color': '#d85d3f', 'border-color': '#ffc5a8', width: 38, height: 38 } },
      { selector: 'node[is_entry_point = "true"]', style: { 'border-color': '#e5c56d', 'border-width': 4 } },
      { selector: 'node[vulnerability_count > 0]', style: { 'background-color': '#b6854c' } },
      { selector: 'edge', style: { width: 1.5, 'line-color': '#58766d', 'curve-style': 'bezier' } },
      { selector: ':selected', style: { 'border-color': '#fff', 'border-width': 4 } },
    ] });
    cy.on('tap', 'node', event => onSelect?.(event.target.data()));
    return () => cy.destroy();
  }, [network, onSelect]);
  return <section className="panel graph-panel"><div className="panel-head"><div><span className="kicker">ATTACK SURFACE</span><h2>Undirected network graph</h2></div><div className="legend"><span><i className="dot entry" />Entry</span><span><i className="dot vuln" />Two findings</span><span><i className="dot critical" />Critical</span></div></div><div ref={containerRef} className="cy-graph" />{!network?.nodes?.length && <div className="empty-state">No network nodes available.</div>}</section>;
}
