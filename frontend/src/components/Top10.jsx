function formatPath(path) {
  if (Array.isArray(path)) return path.join(' → ');
  return String(path || '').replace(/[\[\],]/g, '').trim().replace(/\s+/g, ' → ');
}

export default function Top10({ recommendations, onSelect, activePatches = [], onTogglePatch }) {
  return (
    <section className="panel top-panel">
      <div className="panel-head">
        <div>
          <span className="kicker">PATCH IMPACT</span>
          <h2>Top recommendations</h2>
        </div>
        <span className="panel-note">measured reduction (CRN)</span>
      </div>
      <div className="recommendations">
        {recommendations?.length ? (
          recommendations.map((item, index) => {
            const isPatched = activePatches.includes(item.vulnerability_id);
            return (
              <div
                className={`recommendation ${index < 3 ? 'featured' : ''} ${isPatched ? 'rec-patched' : ''}`}
                key={`${item.host_id}-${item.vulnerability_id}`}
                onClick={() => onSelect?.(item)}
                style={{ cursor: 'pointer' }}
              >
                <span className="rec-rank">{String(item.rank).padStart(2, '0')}</span>
                <span className="rec-main">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <b>{item.vulnerability_id}</b>
                    {isPatched && <span className="patch-badge active">PATCHED</span>}
                  </div>
                  <small>Host {item.host_id}</small>
                  <em className="rec-path">{formatPath(item.associated_path)}</em>
                </span>
                <span className="rec-value">
                  <b>{Number(item.risk_reduction_percent).toFixed(1)}%</b>
                  <small>{Number(item.patch_value).toFixed(3)} risk reduction</small>
                </span>
              </div>
            );
          })
        ) : (
          <div className="empty-state">No recommendations available.</div>
        )}
      </div>
    </section>
  );
}
