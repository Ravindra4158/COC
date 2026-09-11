function Metric({ label, value, detail, accent }) { return <div className={`metric ${accent ? 'accent' : ''}`}><span className="metric-label">{label}</span><strong>{value}</strong><span className="metric-detail">{detail}</span></div>; }

export default function RiskSummary({ summary, recommendations }) {
  const topPatch = recommendations?.[0]?.patch_value ?? 0;
  const topReduction = recommendations?.[0]?.risk_reduction_percent ?? 0;
  return <section className="metrics"><Metric label="Weighted baseline risk" value={summary.baseline_risk.toFixed(3)} detail={`${(summary.critical_asset_reach_probability * 100).toFixed(0)}% critical-asset exposure`} accent /><Metric label="Critical assets" value={`${summary.reachable_critical_assets} / ${summary.critical_assets}`} detail={`${summary.attack_paths} shortest path witnesses`} /><Metric label="Ranked findings" value={summary.total_vulnerabilities} detail={`${summary.candidate_count} path-associated candidates`} /><Metric label="Best single patch" value={`${Number(topReduction).toFixed(1)}%`} detail={`${topPatch.toFixed(3)} risk value · ${summary.total_simulations.toLocaleString()} simulations`} /></section>;
}
