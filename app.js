const { useState, useEffect, useRef } = React;

// Helper: Color based on score
function getGradeColor(grade) {
  switch (grade) {
    case 'A+': return '#10b981'; // emerald-500
    case 'A': return '#22c55e';  // green-500
    case 'B': return '#3b82f6';  // blue-500
    case 'C': return '#f59e0b';  // amber-500
    case 'D': return '#f97316';  // orange-500
    case 'F': return '#ef4444';  // red-500
    default: return '#64748b';
  }
}

// Gauge Chart Component
function GaugeChart({ score = 0, grade = '?', gradeLabel = '' }) {
  const radius = 80;
  const stroke = 14;
  const normalizedRadius = radius - stroke * 2;
  const circumference = normalizedRadius * 2 * Math.PI;
  // Use semi-circle: 180 degrees
  const strokeDashoffset = circumference - (score / 100) * (circumference * 0.75);
  const color = getGradeColor(grade);

  return (
    <div className="flex flex-col items-center justify-center relative p-4">
      <div className="relative w-48 h-48 flex items-center justify-center">
        <svg height="190" width="190" className="transform -rotate-90">
          <circle
            stroke="#1e293b"
            fill="transparent"
            strokeWidth={stroke}
            r={normalizedRadius}
            cx="95"
            cy="95"
          />
          <circle
            stroke={color}
            fill="transparent"
            strokeWidth={stroke}
            strokeDasharray={circumference + ' ' + circumference}
            style={{ strokeDashoffset }}
            strokeLinecap="round"
            className="gauge-arc transition-all duration-1000 ease-out"
            r={normalizedRadius}
            cx="95"
            cy="95"
          />
        </svg>
        <div className="absolute flex flex-col items-center justify-center text-center">
          <span className="text-4xl font-extrabold tracking-tight" style={{ color }}>{grade}</span>
          <span className="text-2xl font-bold text-slate-100">{score}<span className="text-xs text-slate-400">/100</span></span>
          <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-wider mt-0.5">Health Score</span>
        </div>
      </div>
      <p className="text-sm font-medium text-slate-300 mt-1">{gradeLabel || 'Posture Grade'}</p>
    </div>
  );
}

// Main App Component
function App() {
  const [urlInput, setUrlInput] = useState('');
  const [activeScanId, setActiveScanId] = useState(null);
  const [scanStatus, setScanStatus] = useState(null);
  const [scanReport, setScanReport] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [filterTab, setFilterTab] = useState('all'); // all, failed, warning, passed
  const [expandedChecks, setExpandedChecks] = useState({});
  const [copiedSnippetId, setCopiedSnippetId] = useState(null);
  const [activeSnippetTab, setActiveSnippetTab] = useState({});

  const pollIntervalRef = useRef(null);

  // Fetch scan history on load
  const loadHistory = async () => {
    setHistoryLoading(true);
    try {
      const res = await fetch('/api/history');
      if (res.ok) {
        const data = await res.json();
        setHistory(data.history || []);
      }
    } catch (e) {
      console.error('Failed to load history:', e);
    } finally {
      setHistoryLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  // Poll scan status every 2 seconds
  useEffect(() => {
    if (!activeScanId || !isScanning) return;

    const checkStatus = async () => {
      try {
        const res = await fetch(`/api/scan/${activeScanId}/status`);
        if (!res.ok) throw new Error('Status polling failed');
        const data = await res.json();
        setScanStatus(data);

        if (data.status === 'completed') {
          setIsScanning(false);
          clearInterval(pollIntervalRef.current);
          fetchReport(activeScanId);
          loadHistory();
        } else if (data.status === 'failed') {
          setIsScanning(false);
          clearInterval(pollIntervalRef.current);
          setError(data.error_message || 'Scan failed to complete.');
          loadHistory();
        }
      } catch (err) {
        console.error('Polling error:', err);
      }
    };

    // Immediate first check
    checkStatus();
    pollIntervalRef.current = setInterval(checkStatus, 2000);

    return () => clearInterval(pollIntervalRef.current);
  }, [activeScanId, isScanning]);

  const fetchReport = async (scanId) => {
    try {
      const res = await fetch(`/api/scan/${scanId}/report`);
      if (res.ok) {
        const data = await res.json();
        setScanReport(data.report);
      }
    } catch (err) {
      setError('Failed to load report data: ' + err.message);
    }
  };

  const handleStartScan = async (e) => {
    if (e) e.preventDefault();
    if (!urlInput.trim()) return;

    setError(null);
    setScanReport(null);
    setScanStatus(null);
    setIsScanning(true);

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlInput.trim() })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Failed to initiate scan.');
      }

      setActiveScanId(data.scan_id);
      setScanStatus(data);
    } catch (err) {
      setIsScanning(false);
      setError(err.message);
    }
  };

  const loadPastScan = (scanId) => {
    setActiveScanId(scanId);
    setIsScanning(false);
    setError(null);
    fetchReport(scanId);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const toggleCheckExpand = (id) => {
    setExpandedChecks(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const setSnippetConfig = (checkId, configType) => {
    setActiveSnippetTab(prev => ({ ...prev, [checkId]: configType }));
  };

  const copyToClipboard = (text, snippetKey) => {
    navigator.clipboard.writeText(text);
    setCopiedSnippetId(snippetKey);
    setTimeout(() => setCopiedSnippetId(null), 2000);
  };

  // Filter checks list
  const filteredChecks = scanReport?.all_checks ? scanReport.all_checks.filter(c => {
    if (filterTab === 'failed') return c.status === 'FAILED';
    if (filterTab === 'warning') return c.status === 'WARNING';
    if (filterTab === 'passed') return c.status === 'PASSED';
    return true;
  }) : [];

  return (
    <div className="flex-grow flex flex-col">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-sky-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-sky-500/20 text-white font-bold text-xl">
              🛡️
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                VulnScan <span className="text-sky-400 font-semibold text-sm bg-sky-950/80 px-2 py-0.5 rounded border border-sky-800/60">Lite</span>
              </h1>
              <p className="text-xs text-slate-400">On-Demand Web Security Posture & Vulnerability Scanner</p>
            </div>
          </div>
          <div className="flex items-center gap-3 text-xs">
            <a href="/docs" target="_blank" className="text-slate-400 hover:text-slate-200 transition-colors hidden sm:block">
              API Documentation
            </a>
            <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5 animate-ping"></span>
              Scanner Engine Live
            </span>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="max-w-7xl mx-auto px-4 py-8 flex-grow w-full space-y-8">
        
        {/* Search & URL Input Bar */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
          <div className="absolute top-0 right-0 w-96 h-96 bg-sky-500/5 rounded-full blur-3xl -z-0 pointer-events-none"></div>
          
          <div className="max-w-3xl mx-auto text-center space-y-2 mb-6 relative z-10">
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Analyze Any Website's Defensive Posture
            </h2>
            <p className="text-sm text-slate-400">
              Instant non-aggressive health report verifying HTTP headers, SSL/TLS certificates, cipher suites, and outdated CMS platforms.
            </p>
          </div>

          <form onSubmit={handleStartScan} className="max-w-3xl mx-auto relative z-10 space-y-3">
            <div className="flex flex-col sm:flex-row gap-2">
              <div className="relative flex-grow">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                  🌐
                </div>
                <input
                  type="text"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="Enter target domain or URL (e.g. example.com or https://myblog.com)"
                  className="w-full pl-10 pr-4 py-3 bg-slate-950/90 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-sky-500 focus:border-transparent text-sm transition"
                  disabled={isScanning}
                />
              </div>
              <button
                type="submit"
                disabled={isScanning || !urlInput.trim()}
                className="px-6 py-3 bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-semibold rounded-xl text-sm transition-all shadow-lg shadow-sky-500/25 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 whitespace-nowrap"
              >
                {isScanning ? (
                  <>
                    <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Auditing Host...
                  </>
                ) : (
                  <>
                    <span>Run Health Scan</span>
                    <span>⚡</span>
                  </>
                )}
              </button>
            </div>

            {/* Quick Suggestions */}
            <div className="flex items-center gap-2 text-xs text-slate-400 pt-1 flex-wrap">
              <span>Quick test targets:</span>
              {['example.com', 'google.com', 'github.com', 'scanme.nmap.org'].map(preset => (
                <button
                  key={preset}
                  type="button"
                  onClick={() => setUrlInput(preset)}
                  className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                >
                  {preset}
                </button>
              ))}
            </div>
          </form>

          {/* Error message */}
          {error && (
            <div className="max-w-3xl mx-auto mt-4 p-3 bg-red-950/80 border border-red-800/80 rounded-xl text-red-200 text-xs flex items-center gap-2">
              <span>⚠️</span>
              <span>{error}</span>
            </div>
          )}
        </div>

        {/* Live Scan In-Progress Card */}
        {isScanning && scanStatus && (
          <div className="bg-slate-900 border border-sky-900/60 rounded-2xl p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="relative flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-sky-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-sky-500"></span>
                </span>
                <div>
                  <h3 className="font-semibold text-white text-sm">Passive Vulnerability Audit in Progress</h3>
                  <p className="text-xs text-slate-400 font-mono">Target: {scanStatus.target_url}</p>
                </div>
              </div>
              <span className="text-xs font-mono text-sky-400 font-semibold">{scanStatus.progress || 10}%</span>
            </div>

            {/* Progress Bar */}
            <div className="w-full bg-slate-950 rounded-full h-2.5 overflow-hidden border border-slate-800">
              <div
                className="bg-gradient-to-r from-sky-500 to-indigo-500 h-2.5 rounded-full transition-all duration-500"
                style={{ width: `${scanStatus.progress || 10}%` }}
              ></div>
            </div>

            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="flex items-center gap-1.5 text-slate-300">
                <span className="animate-pulse">🔄</span>
                {scanStatus.stage || 'Executing modules...'}
              </span>
              <span>Worker queue polling (2s interval)</span>
            </div>
          </div>
        )}

        {/* Scan Results Card */}
        {scanReport && (
          <div className="space-y-6">
            
            {/* Executive Report Card */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
              <div className="flex flex-col lg:flex-row items-center justify-between gap-6 pb-6 border-b border-slate-800">
                
                {/* Left: Target & Meta */}
                <div className="space-y-3 text-center lg:text-left">
                  <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-slate-800 text-xs text-slate-300 font-medium">
                    <span>Audit Target:</span>
                    <span className="font-mono text-sky-400 font-bold">{scanReport.target_url}</span>
                  </div>
                  <h2 className="text-2xl sm:text-3xl font-extrabold text-white">
                    Security Posture Report Card
                  </h2>
                  <p className="text-xs text-slate-400 max-w-xl">
                    Comprehensive evaluation of HTTP security headers, TLS configuration, certificate lifespan, and CMS technology fingerprints.
                  </p>
                  
                  {/* Action Buttons: PDF Export */}
                  <div className="pt-2 flex flex-wrap items-center gap-3 justify-center lg:justify-start">
                    <a
                      href={`/api/scan/${activeScanId}/pdf`}
                      target="_blank"
                      download
                      className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded-xl text-xs font-semibold transition-all flex items-center gap-2 shadow-md shadow-sky-600/20"
                    >
                      <span>📥</span>
                      <span>Download Executive PDF Report</span>
                    </a>
                    <button
                      onClick={() => handleStartScan()}
                      className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-medium transition"
                    >
                      🔄 Re-run Scan
                    </button>
                  </div>
                </div>

                {/* Right: Gauge Chart */}
                <div className="flex-shrink-0 bg-slate-950/60 p-4 rounded-2xl border border-slate-800/80 shadow-inner">
                  <GaugeChart
                    score={scanReport.score}
                    grade={scanReport.grade}
                    gradeLabel={scanReport.grade_label}
                  />
                </div>
              </div>

              {/* Stat Metric Cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-6">
                <div className="bg-slate-950/80 border border-emerald-900/40 rounded-xl p-4 text-center">
                  <p className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">Passed Checks</p>
                  <p className="text-2xl font-bold text-white mt-1">{scanReport.passed_count}</p>
                </div>
                <div className="bg-slate-950/80 border border-red-900/40 rounded-xl p-4 text-center">
                  <p className="text-xs font-semibold text-red-400 uppercase tracking-wider">Failed Checks</p>
                  <p className="text-2xl font-bold text-white mt-1">{scanReport.failed_count}</p>
                </div>
                <div className="bg-slate-950/80 border border-amber-900/40 rounded-xl p-4 text-center">
                  <p className="text-xs font-semibold text-amber-400 uppercase tracking-wider">Warnings</p>
                  <p className="text-2xl font-bold text-white mt-1">{scanReport.warning_count}</p>
                </div>
                <div className="bg-slate-950/80 border border-sky-900/40 rounded-xl p-4 text-center">
                  <p className="text-xs font-semibold text-sky-400 uppercase tracking-wider">Total Audited</p>
                  <p className="text-2xl font-bold text-white mt-1">{scanReport.total_checks}</p>
                </div>
              </div>

              {/* Technology & SSL Quick Badges */}
              <div className="mt-6 pt-6 border-t border-slate-800 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="bg-slate-950/50 p-3.5 rounded-xl border border-slate-800/80 space-y-1">
                  <p className="text-slate-400 font-semibold flex items-center gap-1.5">
                    <span>🔒</span> SSL / TLS Inspection
                  </p>
                  <p className="text-slate-200">
                    <span className="text-slate-400">Protocol:</span> {scanReport.details?.ssl_tls?.tls_version || 'N/A'} &bull; <span className="text-slate-400">Cipher:</span> {scanReport.details?.ssl_tls?.cipher || 'N/A'}
                  </p>
                  <p className="text-slate-200">
                    <span className="text-slate-400">Issuer CA:</span> {scanReport.details?.ssl_tls?.issuer || 'N/A'}
                  </p>
                  <p className="text-slate-200">
                    <span className="text-slate-400">Days to Expiry:</span> {scanReport.details?.ssl_tls?.days_until_expiry !== null ? `${scanReport.details?.ssl_tls?.days_until_expiry} days` : 'N/A'}
                  </p>
                </div>

                <div className="bg-slate-950/50 p-3.5 rounded-xl border border-slate-800/80 space-y-1">
                  <p className="text-slate-400 font-semibold flex items-center gap-1.5">
                    <span>🧩</span> CMS & Stack Fingerprinting
                  </p>
                  <p className="text-slate-200">
                    <span className="text-slate-400">Platform:</span> {scanReport.details?.cms_tech?.detected_cms ? `${scanReport.details?.cms_tech?.detected_cms} ${scanReport.details?.cms_tech?.cms_version || ''}` : 'No known CMS fingerprint'}
                  </p>
                  <p className="text-slate-200">
                    <span className="text-slate-400">Meta Generator:</span> {scanReport.details?.cms_tech?.generator_tag || 'Concealed / None'}
                  </p>
                  <p className="text-slate-200">
                    <span className="text-slate-400">Identified Tech:</span> {scanReport.details?.cms_tech?.tech_stack?.join(', ') || 'Clean surface'}
                  </p>
                </div>
              </div>
            </div>

            {/* Checks Filter & List */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h3 className="text-lg font-bold text-white">Detailed Audit Findings</h3>
                  <p className="text-xs text-slate-400">Explore security checks and copy server-specific remediation configurations.</p>
                </div>
                
                {/* Tabs */}
                <div className="flex bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
                  {[
                    { id: 'all', label: `All (${scanReport.total_checks})` },
                    { id: 'failed', label: `Failed (${scanReport.failed_count})` },
                    { id: 'warning', label: `Warnings (${scanReport.warning_count})` },
                    { id: 'passed', label: `Passed (${scanReport.passed_count})` }
                  ].map(tab => (
                    <button
                      key={tab.id}
                      onClick={() => setFilterTab(tab.id)}
                      className={`px-3 py-1.5 rounded-lg font-medium transition ${
                        filterTab === tab.id
                          ? 'bg-sky-600 text-white shadow'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      {tab.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Items List */}
              <div className="space-y-3">
                {filteredChecks.length === 0 ? (
                  <div className="text-center py-8 text-slate-500 text-sm">
                    No checks match the selected filter.
                  </div>
                ) : (
                  filteredChecks.map((chk, idx) => {
                    const isExpanded = expandedChecks[chk.id] !== false; // default expanded
                    const isFailed = chk.status === 'FAILED';
                    const isWarning = chk.status === 'WARNING';
                    const isPassed = chk.status === 'PASSED';
                    const rem = chk.remediation;
                    const snippetKey = `${chk.id}_${activeSnippetTab[chk.id] || 'nginx'}`;

                    return (
                      <div
                        key={chk.id || idx}
                        className={`border rounded-xl transition-all ${
                          isFailed
                            ? 'bg-red-950/20 border-red-900/40 hover:border-red-800/60'
                            : isWarning
                            ? 'bg-amber-950/20 border-amber-900/40 hover:border-amber-800/60'
                            : 'bg-slate-950/40 border-slate-800/70 hover:border-slate-700'
                        }`}
                      >
                        {/* Summary Header */}
                        <div
                          className="p-4 cursor-pointer flex items-center justify-between gap-4"
                          onClick={() => toggleCheckExpand(chk.id)}
                        >
                          <div className="flex items-start gap-3">
                            <span className="mt-0.5 text-base">
                              {isPassed ? '✅' : isFailed ? '❌' : '⚠️'}
                            </span>
                            <div>
                              <div className="flex items-center gap-2 flex-wrap">
                                <h4 className="font-semibold text-white text-sm">{chk.name}</h4>
                                <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${
                                  isPassed ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/60' :
                                  isFailed ? 'bg-red-950 text-red-400 border border-red-800/60' :
                                  'bg-amber-950 text-amber-400 border border-amber-800/60'
                                }`}>
                                  {chk.status} ({chk.points > 0 ? `+${chk.points}` : chk.points} pts)
                                </span>
                                <span className="text-[10px] text-slate-500 font-mono">
                                  {chk.category}
                                </span>
                              </div>
                              <p className="text-xs text-slate-300 mt-1">{chk.message}</p>
                            </div>
                          </div>

                          <div className="text-slate-400 text-xs">
                            {isExpanded ? '▲' : '▼'}
                          </div>
                        </div>

                        {/* Expandable Remediation & Risk Drawer */}
                        {isExpanded && (
                          <div className="px-4 pb-4 pt-1 border-t border-slate-800/50 space-y-3 text-xs">
                            {chk.risk && (
                              <div className="p-3 bg-red-950/40 rounded-lg border border-red-900/30 text-red-200">
                                <span className="font-bold text-red-300">Security Risk: </span>
                                {chk.risk}
                              </div>
                            )}

                            {chk.description && (
                              <p className="text-slate-400">
                                <span className="text-slate-300 font-medium">Description: </span>
                                {chk.description}
                              </p>
                            )}

                            {/* Remediation Snippet Block */}
                            {rem && (
                              <div className="bg-slate-950 rounded-xl p-3 border border-slate-800 space-y-2">
                                <div className="flex items-center justify-between flex-wrap gap-2">
                                  <span className="font-semibold text-sky-400 flex items-center gap-1.5">
                                    <span>🛠️</span> How to Fix ({rem.title})
                                  </span>

                                  {/* Config Tabs: Nginx, Apache, Caddy, Express */}
                                  <div className="flex gap-1 bg-slate-900 p-0.5 rounded-lg border border-slate-800 text-[11px]">
                                    {['nginx', 'apache', 'caddy', 'express'].map(cfg => rem[cfg] && (
                                      <button
                                        key={cfg}
                                        type="button"
                                        onClick={() => setSnippetConfig(chk.id, cfg)}
                                        className={`px-2 py-0.5 rounded uppercase font-mono font-medium transition ${
                                          (activeSnippetTab[chk.id] || 'nginx') === cfg
                                            ? 'bg-sky-600 text-white'
                                            : 'text-slate-400 hover:text-slate-200'
                                        }`}
                                      >
                                        {cfg}
                                      </button>
                                    ))}
                                  </div>
                                </div>

                                <p className="text-slate-400 text-[11px]">{rem.summary}</p>

                                {/* Code Display */}
                                {rem[activeSnippetTab[chk.id] || 'nginx'] && (
                                  <div className="relative group mt-1">
                                    <pre className="p-3 bg-slate-900 rounded-lg text-slate-200 font-mono text-[11px] overflow-x-auto border border-slate-800">
                                      <code>{rem[activeSnippetTab[chk.id] || 'nginx']}</code>
                                    </pre>
                                    <button
                                      type="button"
                                      onClick={() => copyToClipboard(rem[activeSnippetTab[chk.id] || 'nginx'], snippetKey)}
                                      className="absolute top-2 right-2 px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[10px] font-medium transition border border-slate-700 flex items-center gap-1"
                                    >
                                      {copiedSnippetId === snippetKey ? '✓ Copied!' : '📋 Copy'}
                                    </button>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          </div>
        )}

        {/* Scan History Section */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-bold text-white">Recent Scan History</h3>
              <p className="text-xs text-slate-400">Chronological audits and security posture tracking over time.</p>
            </div>
            <button
              onClick={loadHistory}
              className="text-xs text-sky-400 hover:text-sky-300 flex items-center gap-1 transition"
            >
              <span>🔄</span> Refresh
            </button>
          </div>

          {historyLoading ? (
            <div className="text-center py-6 text-slate-500 text-xs">Loading scan history...</div>
          ) : history.length === 0 ? (
            <div className="text-center py-8 text-slate-500 text-xs">
              No historical scans recorded yet. Run your first scan above!
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] font-semibold tracking-wider">
                  <tr>
                    <th className="py-3 px-4 rounded-l-lg">Target Host</th>
                    <th className="py-3 px-4">Score</th>
                    <th className="py-3 px-4">Grade</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Date (UTC)</th>
                    <th className="py-3 px-4 rounded-r-lg text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {history.map(item => (
                    <tr key={item.scan_id} className="hover:bg-slate-800/30 transition">
                      <td className="py-3 px-4 font-mono font-medium text-white max-w-[200px] truncate">
                        {item.target_url}
                      </td>
                      <td className="py-3 px-4">
                        {item.score !== null ? (
                          <span className="font-bold">{item.score} / 100</span>
                        ) : '—'}
                      </td>
                      <td className="py-3 px-4">
                        {item.grade ? (
                          <span
                            className="px-2 py-0.5 rounded text-[11px] font-bold"
                            style={{
                              backgroundColor: `${getGradeColor(item.grade)}20`,
                              color: getGradeColor(item.grade)
                            }}
                          >
                            {item.grade}
                          </span>
                        ) : '—'}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                          item.status === 'completed' ? 'bg-emerald-950 text-emerald-400' :
                          item.status === 'failed' ? 'bg-red-950 text-red-400' : 'bg-sky-950 text-sky-400'
                        }`}>
                          {item.status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-400">
                        {item.created_at ? item.created_at.slice(0, 16).replace('T', ' ') : 'N/A'}
                      </td>
                      <td className="py-3 px-4 text-right space-x-2">
                        {item.status === 'completed' && (
                          <>
                            <button
                              onClick={() => loadPastScan(item.scan_id)}
                              className="px-2.5 py-1 bg-sky-950 hover:bg-sky-900 text-sky-300 rounded border border-sky-800/60 text-[11px] font-medium transition"
                            >
                              View Report
                            </button>
                            <a
                              href={`/api/scan/${item.scan_id}/pdf`}
                              download
                              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px] font-medium transition inline-block"
                            >
                              PDF
                            </a>
                          </>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-slate-900 py-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-300">VulnScan Lite</span>
            <span>&bull;</span>
            <span>Defensive Posture Security Engine</span>
          </div>
          <p>
            Designed for educational and defensive auditing. Performs non-destructive analysis.
          </p>
        </div>
      </footer>
    </div>
  );
}

// Mount React App
ReactDOM.render(<App />, document.getElementById('root'));
