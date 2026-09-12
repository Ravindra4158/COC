const API_BASE = import.meta.env.VITE_API_URL || (import.meta.env.PROD ? '/api' : 'http://localhost:8000');

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, options);
  if (!response.ok) throw new Error(`Request failed: ${response.status}`);
  return response.json();
}

export const getAnalysis = () => request('/analysis');
export const getNetwork = () => request('/network');
export const getVulnerabilities = () => request('/vulnerabilities');
export const getRecommendations = () => request('/recommendations');
export const runAnalysis = (params = {}) => request('/analysis/run', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(params),
});
export const resetAnalysis = () => request('/analysis/reset', { method: 'POST' });
