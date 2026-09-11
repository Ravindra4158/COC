import { useCallback, useEffect, useState } from 'react';
import LoadingState from './components/LoadingState';
import NetworkGraph from './components/NetworkGraph';
import RiskChart from './components/RiskChart';
import RiskSummary from './components/RiskSummary';
import Top10 from './components/Top10';
import VulnerabilityTable from './components/VulnerabilityTable';
import { getAnalysis, getNetwork, getRecommendations, getVulnerabilities, runAnalysis } from './services/api';

const PAGES = [
  ['overview', 'Overview'],
  ['network', 'Network'],
  ['findings', 'Findings'],
  ['patches', 'Patch plan'],
  ['method', 'Method'],
];

function pathText(path) {
  return Array.isArray(path) ? path.join(' → ') : String(path || '').replace(/[\[\],]/g, '').trim().replace(/\s+/g, ' → ');
}

function FindingDetail({ item }) {
  if (!item) return <aside className="detail-card empty-state">Choose a finding or a node to inspect its evidence.</aside>;
  const path = pathText(item.associated_path);
  return <aside className="detail-card"><span className="eyebrow">SELECTED EVIDENCE</span><h2>{item.vulnerability_id} <small>host {item.host_id}</small></h2><p>{item.reason || 'Graph-aware priority and virtual patch measurements are shown for this finding.'}</p>{path && <div className="path-witness"><span>ENTRY → CRITICAL PATH</span><b>{path}</b></div>}<div className="evidence"><div><span>Priority</span><b>{Number(item.priority_score).toFixed(1)}</b></div><div><span>CVSS</span><b>{Number(item.cvss).toFixed(1)}</b></div><div><span>Reach</span><b>{(Number(item.attacker_reachability) * 100).toFixed(0)}%</b></div><div><span>Exposure</span><b>{(Number(item.critical_asset_exposure) * 100).toFixed(0)}%</b></div><div><span>Reduction</span><b>{(Number(item.risk_reduction_percent) || 0).toFixed(1)}%</b></div><div><span>Patch value</span><b>{Number(item.patch_value || 0).toFixed(3)}</b></div></div></aside>;
}

function MethodPage({ summary }) {
  return <section className="method-page"><div className="method-hero"><span className="eyebrow">HOW TO READ THIS ANALYSIS</span><h2>Risk is measured through the graph—not severity alone.</h2><p>Each vulnerability is evaluated in its network context: entry reachability, downstream critical assets, exploit likelihood, and the measured effect of virtual patching.</p></div><div className="method-grid"><article><b>01</b><h3>Generate or ingest</h3><p>Load the evaluation graph and its host-vulnerability pairs. The local development instance is reproducible; supplied evaluator data takes priority.</p></article><article><b>02</b><h3>Model attack reach</h3><p>Attackers begin at declared entry nodes and can enter a neighboring host only when an unpatched finding succeeds.</p></article><article><b>03</b><h3>Rank contextual risk</h3><p>Priority combines exploitability, severity, graph reachability, asset exposure, and structural importance.</p></article><article><b>04</b><h3>Test patches</h3><p>Virtual patching estimates the weighted reduction in critical-asset risk under the shared simulation budget.</p></article></div><div className="method-foot"><span>RUN STATUS</span><b>{summary.total_simulations.toLocaleString()} simulations used · {summary.candidate_count} path-associated candidates · {summary.top10_count || 10} recommendations</b></div></section>;
}

export default function App() {
  const [data, setData] = useState(null);
  const [selected, setSelected] = useState(null);
  const [page, setPage] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');
  const load = useCallback(async () => { setLoading(true); setError(''); try { const [summary, network, vulnerabilities, recommendations] = await Promise.all([getAnalysis(), getNetwork(), getVulnerabilities(), getRecommendations()]); setData({ summary, network, vulnerabilities: vulnerabilities.items, recommendations: recommendations.items }); } catch { setError('Unable to connect to the analysis server. Start FastAPI with uvicorn app.main:app --reload.'); } finally { setLoading(false); } }, []);
  useEffect(() => { load(); }, [load]);
  const refresh = async () => { setRunning(true); setError(''); try { await runAnalysis(); await load(); } catch { setError('Analysis refresh failed. Check the backend logs.'); } finally { setRunning(false); } };
  const chooseNode = node => setSelected(data.vulnerabilities.find(item => String(item.host_id) === String(node.id)) || { host_id: node.id, vulnerability_id: 'Host detail', priority_score: 0, cvss: 0, attacker_reachability: 0, critical_asset_exposure: 0, patch_value: 0, risk_reduction_percent: 0 });
  const content = data && {
    overview: <><RiskSummary summary={data.summary} recommendations={data.recommendations} /><div className="overview-grid"><NetworkGraph network={data.network} onSelect={chooseNode} /><Top10 recommendations={data.recommendations.slice(0, 5)} onSelect={setSelected} /></div><div className="split-grid"><RiskChart items={data.vulnerabilities} /><FindingDetail item={selected || data.recommendations[0]} /></div></>,
    network: <section className="single-view"><div className="view-intro"><span className="eyebrow">NETWORK EXPLORER</span><h2>Explore entry points, findings, and critical assets.</h2><p>Select a host to inspect the finding attached to it.</p></div><NetworkGraph network={data.network} onSelect={chooseNode} /><FindingDetail item={selected} /></section>,
    findings: <section className="single-view"><div className="view-intro"><span className="eyebrow">FULL RANKING</span><h2>All host-vulnerability pairs</h2><p>Sort and search the complete queue. Priority is contextual; patch value is measured separately.</p></div><VulnerabilityTable items={data.vulnerabilities} onSelect={setSelected} /><FindingDetail item={selected} /></section>,
    patches: <section className="patch-page"><div className="view-intro"><span className="eyebrow">REMEDIATION PLAN</span><h2>Ten patches with path evidence</h2><p>Each recommendation includes an entry-to-critical path through its affected host and a numeric virtual-patch estimate.</p></div><div className="patch-layout"><Top10 recommendations={data.recommendations} onSelect={setSelected} /><FindingDetail item={selected || data.recommendations[0]} /></div></section>,
    method: <MethodPage summary={data.summary} />,
  }[page];
  return <div className="app-shell"><aside className="sidebar"><div className="logo"><span>CY</span><b>02</b></div><div className="sidebar-label">ANALYSIS WORKSPACE</div><nav>{PAGES.map(([id, label], index) => <button key={id} className={page === id ? 'nav-active' : ''} onClick={() => setPage(id)}><span>0{index + 1}</span>{label}</button>)}</nav><div className="sidebar-foot"><span>DEVELOPMENT INSTANCE</span><b>Graph-aware prioritization</b></div></aside><main className="workspace"><header className="topbar"><div><span className="eyebrow">CY-02 · SECURITY DECISION SUPPORT</span><h1>{PAGES.find(([id]) => id === page)?.[1]}</h1></div><div className="top-actions"><span>{data?.summary?.updated_at ? `Updated ${new Date(data.summary.updated_at).toLocaleTimeString()}` : 'Loading analysis'}</span><button onClick={refresh} disabled={running}>{running ? 'Running analysis…' : 'Run analysis'}</button></div></header>{error && <div className="error-banner"><span>{error}</span><button onClick={load}>Retry</button></div>}{loading ? <LoadingState /> : content}</main></div>;
}
