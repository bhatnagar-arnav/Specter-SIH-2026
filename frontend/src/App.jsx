import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Upload, Search, Trash2, Maximize2, Minimize2, Download } from 'lucide-react';
import NetworkGraph from './NetworkGraph';

const API_BASE = 'http://localhost:8000/api';

const SpecterLogo = ({ className = "w-8 h-8" }) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className={className}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M12 2L2 7l10 5 10-5-10-5z" />
    <path strokeLinecap="round" strokeLinejoin="round" d="M2 17l10 5 10-5" />
    <path strokeLinecap="round" strokeLinejoin="round" d="M2 12l10 5 10-5" />
  </svg>
);

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [rawText, setRawText] = useState("");
  const [formData, setFormData] = useState({
      case_summary: "",
      threat_actors: [],
      ip_addresses: [],
      crypto_wallets: [],
      onion_domains: [],
      pgp_keys: [],
      linguistic_markers: [],
      forensic_hash: "",
      ingested_at: ""
  });
  const [isExtracting, setIsExtracting] = useState(false);
  const [reports, setReports] = useState([]);
  const [showUpload, setShowUpload] = useState(false);
  const [uploadFile, setUploadFile] = useState(null);
  
  const [graphData, setGraphData] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [alertMsg, setAlertMsg] = useState(null);
  const [isGraphExpanded, setIsGraphExpanded] = useState(false);

  const [isLoading, setIsLoading] = useState(false);

  const fetchIntel = async () => {
    try {
      const res = await axios.get(`${API_BASE}/intel-reports`);
      if (res.data?.reports) setReports(res.data.reports);
    } catch (e) {
      console.warn('Could not fetch intel reports', e);
    }
  };

  useEffect(() => {
    fetchIntel();
  }, []);

  useEffect(() => {
    if (graphData) {
      const edges = graphData.edges;
      const nodes = graphData.nodes;
      
      const nexusNode = nodes.reduce((max, node) => 
          (node.metrics?.betweenness_centrality || 0) > (max.metrics?.betweenness_centrality || 0) ? node : max
      , { metrics: { betweenness_centrality: 0 } });

      if (nexusNode && nexusNode.metrics?.betweenness_centrality > 0.4 && nexusNode.label !== 'Intel_Report') {
          const connectedReports = edges
              .filter(edge => edge.from === nexusNode.id || edge.to === nexusNode.id)
              .map(edge => edge.from === nexusNode.id ? edge.to : edge.from)
              .filter(id => {
                  const node = nodes.find(n => n.id === id);
                  return node && (node.label === 'Intel_Report' || String(node.name).startsWith('INTEL_'));
              });

          const uniqueReports = [...new Set(connectedReports)];

          if (uniqueReports.length >= 2) {
              const nodeName = nexusNode.name || nexusNode.label || "Unknown Actor";
              const score = parseFloat(nexusNode.metrics.betweenness_centrality).toFixed(2);
              setAlertMsg(`🚨 ALERT: Syndicate detected! Threat Actor [${nodeName}] (Centrality: ${score}) bridges ${uniqueReports.length} distinct operations.`);
              return;
          }
      }
      setAlertMsg(null);
    } else {
      setAlertMsg(null);
    }
  }, [graphData]);

  const loadIntel = async (intelId) => {
    setIsLoading(true);
    try {
        const response = await fetch(`${API_BASE}/intel-report/${intelId}`);
        if (!response.ok) throw new Error("Failed to fetch intel data");
        const data = await response.json();

        setRawText(data.raw_text);
        setFormData({
            case_summary: data.case_summary || "",
            threat_actors: data.threat_actors || [],
            ip_addresses: data.ip_addresses || [],
            crypto_wallets: data.crypto_wallets || [],
            onion_domains: data.onion_domains || [],
            pgp_keys: data.pgp_keys || [],
            linguistic_markers: data.linguistic_markers || [],
            forensic_hash: data.forensic_hash || "",
            ingested_at: data.ingested_at || ""
        });
    } catch (err) {
        console.error("Error loading intel:", err);
        alert('Failed to load Intelligence Report.');
    } finally {
        setIsLoading(false);
    }
  };

  const handleUploadClick = () => {
      if (!uploadFile) return;
      const reader = new FileReader();
      reader.onload = async (e) => {
          const text = e.target.result;
          setShowUpload(false);
          await handleUpload(text);
      };
      reader.readAsText(uploadFile);
  };

  const handleUpload = async (text) => {
      setRawText(text);
      setIsExtracting(true);
      
      try {
          const response = await fetch(`${API_BASE}/ingest-intel`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ text: text })
          });

          if (!response.ok) {
              const errData = await response.json();
              throw new Error(errData.detail || `Server error: ${response.status}`);
          }

          const data = await response.json();
          
          setFormData({
              case_summary: data.case_summary || "",
              threat_actors: data.threat_actors || [],
              ip_addresses: data.ip_addresses || [],
              crypto_wallets: data.crypto_wallets || [],
              onion_domains: data.onion_domains || [],
              pgp_keys: data.pgp_keys || [],
              linguistic_markers: data.linguistic_markers || [],
              forensic_hash: data.forensic_hash || "",
              ingested_at: data.ingested_at || ""
          });
          setGraphData(null); 
          setUploadFile(null);

      } catch (error) {
          console.error("Extraction failed:", error);
          alert(`Extraction Failed: ${error.message}. Please check the backend logs.`);
      } finally {
          setIsExtracting(false);
      }
  };

  const commitIntel = async () => {
    if (!rawText || !formData) return;
    setIsLoading(true);
    
    const payload = {
      intel_id: crypto.randomUUID(),
      raw_text: rawText,
      case_summary: formData.case_summary,
      threat_actors: formData.threat_actors || [],
      ip_addresses: formData.ip_addresses || [],
      crypto_wallets: formData.crypto_wallets || [],
      onion_domains: formData.onion_domains || [],
      pgp_keys: formData.pgp_keys || [],
      linguistic_markers: formData.linguistic_markers || [],
      forensic_hash: formData.forensic_hash || "",
      ingested_at: formData.ingested_at || ""
    };

    try {
      await axios.post(`${API_BASE}/commit-intel`, payload);
      alert('Verified intel securely committed to Knowledge Graph');
      
      const analyticsRes = await axios.get(`${API_BASE}/analytics`);
      setGraphData(analyticsRes.data);
      
      fetchIntel(); 
    } catch (e) {
      console.error(e);
      alert('Commit failed: ' + (e.response?.data?.detail || e.message));
    } finally {
      setIsLoading(false);
    }
  };

  const deleteIntel = async (intelId) => {
    if (!window.confirm("Are you sure you want to permanently delete this intelligence report and its network links?")) return;
    
    setIsLoading(true);
    try {
      await axios.delete(`${API_BASE}/intel/${intelId}`);
      alert("Intelligence Report deleted successfully.");
      fetchIntel();
      
      const analyticsRes = await axios.get(`${API_BASE}/analytics`);
      setGraphData(analyticsRes.data);
      
      if (searchQuery === intelId) setSearchQuery("");
    } catch (e) {
      console.error(e);
      alert("Failed to delete Intel Report.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearWorkspace = () => {
    setRawText("");
    setFormData({
        case_summary: "",
        threat_actors: [],
        ip_addresses: [],
        crypto_wallets: [],
        onion_domains: [],
        pgp_keys: [],
        linguistic_markers: [],
        forensic_hash: "",
        ingested_at: ""
    });
    setGraphData(null); 
    setAlertMsg(null);
  };

  const handleWipeDatabase = async () => {
    if (!window.confirm("CRITICAL WARNING: This will permanently delete all intel and nodes from the Neo4j database. Continue?")) return;
    
    try {
        const response = await fetch(`${API_BASE}/clear_database`, { method: 'DELETE' });
        if (response.ok) {
            alert("Database successfully wiped.");
            handleClearWorkspace();
            fetchIntel();
        }
    } catch (error) {
        console.error("Failed to wipe database:", error);
    }
  };

  const handleDownloadSTIX = async () => {
    setIsLoading(true);
    try {
        const response = await fetch(`${API_BASE}/export-stix`);
        if (!response.ok) throw new Error("Failed to export STIX");
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'specter_stix_export.json';
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
    } catch (error) {
        console.error("STIX export failed:", error);
        alert("Failed to download STIX Report.");
    } finally {
        setIsLoading(false);
    }
  };

  const handleFieldChange = (field, index, value) => {
    if (field === 'case_summary') {
      setFormData(prev => ({ ...prev, case_summary: value }));
    } else {
      const newList = [...formData[field]];
      newList[index] = value;
      setFormData(prev => ({ ...prev, [field]: newList }));
    }
  };

  const handleAddField = (field) => {
    setFormData(prev => ({
      ...prev,
      [field]: [...prev[field], '']
    }));
  };

  const removeField = (field, index) => {
      const newList = [...formData[field]];
      newList.splice(index, 1);
      setFormData(prev => ({ ...prev, [field]: newList }));
  };

  const renderArrayField = (label, fieldKey) => (
    <div className="mb-4 bg-slate-800 border border-slate-700 p-3 rounded-lg shadow-sm">
      <h3 className="font-semibold mb-2 text-slate-300 text-xs uppercase">{label}</h3>
      {formData[fieldKey].length === 0 ? (
        <p className="text-xs text-slate-500">No entities extracted</p>
      ) : null}
      {formData[fieldKey].map((val, idx) => (
        <div key={idx} className="flex mb-2 gap-2">
          <input
            className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-sm text-slate-200 focus:border-slate-500 focus:ring-1 focus:ring-slate-500 focus:outline-none flex-grow transition-colors"
            value={val}
            onChange={(e) => handleFieldChange(fieldKey, idx, e.target.value)}
          />
          <button onClick={() => removeField(fieldKey, idx)} className="text-slate-500 hover:text-red-400 font-bold px-2 transition-colors">X</button>
        </div>
      ))}
      <button
        onClick={() => handleAddField(fieldKey)}
        className="mt-2 text-slate-200 bg-slate-700 hover:bg-slate-600 font-semibold text-xs rounded px-3 py-1.5 transition-colors"
      >
        + Add {label}
      </button>
    </div>
  );

  if (!isAuthenticated) {
      return (
          <div className="min-h-screen w-screen flex items-center justify-center bg-slate-950 font-sans selection:bg-slate-700 selection:text-white">
              <div className="w-full max-w-md bg-slate-900 border border-slate-800 shadow-2xl rounded-xl p-8">
                  <div className="flex flex-col items-center justify-center mb-8 text-slate-200">
                      <SpecterLogo className="w-16 h-16 mb-4 text-emerald-400" />
                      <h1 className="text-3xl font-black tracking-widest uppercase text-emerald-400">Specter</h1>
                      <p className="text-xs text-slate-400 tracking-widest mt-2 uppercase font-medium">Dark Web De-anonymization System</p>
                  </div>
                  
                  <form onSubmit={(e) => { e.preventDefault(); setIsAuthenticated(true); }} className="space-y-5">
                      <div>
                          <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Analyst ID</label>
                          <input 
                              type="text" 
                              required
                              className="w-full bg-slate-950 border border-slate-800 text-slate-200 placeholder-slate-700 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-all"
                              placeholder="Enter Analyst ID"
                          />
                      </div>
                      <div>
                          <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Secure Passkey</label>
                          <input 
                              type="password" 
                              required
                              className="w-full bg-slate-950 border border-slate-800 text-slate-200 placeholder-slate-700 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-all"
                              placeholder="••••••••"
                          />
                      </div>
                      <button 
                          type="submit" 
                          className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-3 px-4 rounded-lg transition-colors uppercase tracking-widest mt-4 text-xs shadow-lg shadow-emerald-900/50"
                      >
                          Initialize Interface
                      </button>
                  </form>
                  
                  <div className="mt-8 pt-6 border-t border-slate-800 text-center">
                      <p className="text-[10px] text-slate-600 uppercase tracking-wider">
                          Warning: Authorized NTRO personnel only. All access is logged and monitored.
                      </p>
                  </div>
              </div>
          </div>
      );
  }

  return (
    <div className="flex h-screen w-screen bg-slate-950 text-slate-300 overflow-hidden font-sans">
      {/* Loading Overlay */}
      {(isLoading || isExtracting) && (
        <div className="absolute inset-0 bg-slate-950/90 z-[100] flex flex-col items-center justify-center">
          <div className="w-16 h-16 border-4 border-emerald-500 border-t-transparent rounded-full animate-spin"></div>
          <p className="mt-4 text-emerald-500 font-bold tracking-widest uppercase">Analyzing Artifacts...</p>
        </div>
      )}

      {/* Alert Notification */}
      {alertMsg && (
        <div className="absolute top-4 left-1/2 transform -translate-x-1/2 z-50 bg-rose-900 border border-rose-500 text-rose-100 px-4 py-3 rounded shadow-lg animate-pulse">
          <span className="block sm:inline font-bold">{alertMsg}</span>
        </div>
      )}

      {/* Left Sidebar */}
      <div className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col p-4 shadow-xl z-20">
        <div className="flex items-center gap-3 mb-6 pb-4 border-b border-slate-800">
            <SpecterLogo className="w-8 h-8 text-emerald-400" />
            <h1 className="text-xl font-bold tracking-wider text-emerald-400">SPECTER</h1>
        </div>
        
        {/* Upload Button */}
        <button 
          onClick={() => setShowUpload(true)}
          className="flex items-center justify-center w-full bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-2.5 rounded-lg text-xs uppercase mb-3 transition-colors shadow-md shadow-emerald-900/30"
        >
          <Upload className="w-5 h-5 mr-2" />
          Ingest Intel
        </button>

        <div className="flex flex-col gap-2 mt-2 mb-2">
            <button 
                onClick={handleClearWorkspace}
                className="w-full bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 hover:border-slate-500 font-semibold py-2 rounded text-xs transition-colors"
            >
                Clear View
            </button>
            <button 
                onClick={handleWipeDatabase}
                className="w-full bg-rose-950 hover:bg-rose-900 text-rose-400 hover:text-rose-300 border border-rose-900 font-semibold py-2 rounded text-xs transition-colors"
            >
                ⚠️ Nuke Graph Database
            </button>
        </div>

        <div className="text-xs uppercase text-slate-500 font-bold tracking-widest mt-4">Intel Reports</div>
        <div className="flex-grow overflow-y-auto flex flex-col gap-1 max-h-[calc(100vh-200px)] mt-2">
          {reports.map(intelId => (
            <div key={intelId} className="flex justify-between items-center group gap-2">
              <button
                onClick={() => loadIntel(intelId)}
                className="flex-grow text-left font-mono text-xs text-slate-400 hover:text-emerald-400 bg-slate-950 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 rounded px-2.5 py-2 transition-all truncate"
                title={intelId}
              >
                📄 {intelId.slice(0, 8)}...{intelId.slice(-4)}
              </button>
              <button onClick={() => deleteIntel(intelId)} className="text-slate-600 opacity-0 group-hover:opacity-100 hover:text-rose-400 transition-colors p-2">
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          ))}
          {reports.length === 0 && <p className="text-slate-600 text-xs italic">No intel in database.</p>}
        </div>
      </div>

      {/* Primary Viewport */}
      <div className="flex-1 flex flex-col h-full relative overflow-hidden">
        {/* Top Navbar */}
        <div className="bg-slate-900 border-b border-slate-800 p-4 flex justify-between items-center z-10 h-[60px] flex-shrink-0 shadow-md">
          <div className="flex bg-slate-950 border border-slate-800 p-2 rounded w-96 focus-within:border-emerald-500 transition-colors">
            <Search className="w-5 h-5 text-slate-500 mr-2" />
            <input 
              className="bg-transparent outline-none flex-grow text-sm text-slate-300 placeholder-slate-600"
              placeholder="Search threat actor UUID or report..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
            />
          </div>
          <button 
            onClick={handleDownloadSTIX}
            className="flex items-center justify-center bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2 px-4 rounded text-xs uppercase transition-colors shadow-md shadow-indigo-900/30"
          >
            <Download className="w-4 h-4 mr-2" />
            Download STIX Report
          </button>
        </div>

        {/* Split Screen UI & Graph */}
        {rawText ? (
          <div className="flex-grow flex flex-col h-[calc(100vh-60px)]">
            {/* Top Half: Text and Extraction */}
            {!isGraphExpanded && (
            <div className="flex-1 flex overflow-hidden border-b border-slate-800">
              {/* Raw Text Column */}
              <div className="w-1/2 p-4 flex flex-col border-r border-slate-800 bg-slate-950">
                <span className="text-xs font-bold uppercase text-emerald-500 mb-2">Raw Intelligence Intercept</span>
                <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex-1 text-sm text-slate-300 font-mono shadow-inner overflow-y-auto mb-2">
                  <pre className="whitespace-pre-wrap leading-relaxed">
                    {rawText}
                  </pre>
                </div>
                {formData.forensic_hash && (
                  <div className="text-[10px] text-slate-500 font-mono">
                    <p>Forensic Checksum: {formData.forensic_hash}</p>
                    <p>Timestamp: {formData.ingested_at}</p>
                  </div>
                )}
              </div>

              {/* HITL Form Column */}
              <div className="w-1/2 p-4 flex flex-col bg-slate-900 overflow-y-auto">
                <span className="text-xs font-bold uppercase text-emerald-400 mb-2">Analyst Triage Pipeline</span>
                
                <div className="mb-4 bg-slate-800 border border-slate-700 p-3 rounded-lg shadow-sm">
                  <h3 className="font-semibold mb-2 text-slate-300 text-xs uppercase">Intel Summary</h3>
                  <textarea 
                    className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-sm text-slate-300 focus:border-slate-500 focus:outline-none h-20 transition-colors"
                    value={formData.case_summary}
                    onChange={(e) => handleFieldChange('case_summary', null, e.target.value)}
                  />
                </div>

                {renderArrayField('Threat Actors', 'threat_actors')}
                {renderArrayField('IP Addresses', 'ip_addresses')}
                {renderArrayField('Crypto Wallets', 'crypto_wallets')}
                {renderArrayField('Onion Domains', 'onion_domains')}
                {renderArrayField('PGP Keys', 'pgp_keys')}
                {renderArrayField('Linguistic Markers', 'linguistic_markers')}

                <button 
                  onClick={commitIntel}
                  className="w-full mt-auto bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-3 rounded-lg uppercase tracking-wider text-xs shadow-md transition-colors"
                >
                  Commit Triage to Graph
                </button>
              </div>
            </div>
            )}

            {/* Bottom Half: NetworkX Analytics Graph */}
            <div className={`${isGraphExpanded ? 'h-full' : 'h-1/2 flex-shrink-0'} relative bg-slate-950`}>
              {graphData ? (
                <>
                  <div className="absolute top-4 left-4 z-30 flex items-center gap-2">
                    <h3 className="font-bold text-sm bg-slate-900 text-emerald-400 p-2 rounded border border-slate-800 shadow">NetworkX Connectivity View</h3>
                    <button 
                      onClick={() => setIsGraphExpanded(!isGraphExpanded)}
                      className="bg-slate-900 text-slate-400 p-2 rounded border border-slate-800 shadow hover:bg-slate-800 hover:text-emerald-400 transition-colors flex items-center justify-center"
                      title={isGraphExpanded ? "Restore View" : "Expand Graph"}
                    >
                      {isGraphExpanded ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
                    </button>
                  </div>
                  <NetworkGraph data={graphData} onNodeClick={(node) => {
                  }} />
                  <div className="absolute bottom-4 left-4 z-30 bg-slate-900/90 text-slate-300 border border-slate-800 p-3 text-xs rounded shadow-lg backdrop-blur">
                    <div className="font-bold mb-2 border-b border-slate-700 pb-1 text-emerald-500 uppercase tracking-widest">Analytics Legend</div>
                    <div className="flex flex-col gap-2 mt-2">
                      <div className="flex items-center gap-2">
                        <div className="w-4 h-4 rounded bg-emerald-500"></div><span className="text-sm">Verified Artifacts</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <div className="w-4 h-4 rounded bg-slate-500"></div><span className="text-sm">Intel Report</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <div className="w-4 h-4 rounded-full bg-rose-500 shadow-[0_0_10px_#f43f5e]"></div><span className="text-sm">Nexus Threat Actor (Centrality &gt; 0.4)</span>
                      </div>
                    </div>
                  </div>
                </>
              ) : (
                <div className="flex h-full items-center justify-center text-slate-700 font-semibold tracking-widest uppercase text-sm">
                  Waiting for Neo4j Commit...
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="flex-grow flex items-center justify-center text-slate-700 font-semibold tracking-widest uppercase">
            System Idle. Ingest Intelligence to begin.
          </div>
        )}
      </div>

      {/* Upload Modal */}
      {showUpload && (
        <div className="absolute inset-0 bg-slate-950/80 flex items-center justify-center z-50 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl shadow-2xl w-96 transform transition-all">
            <h2 className="text-xl font-bold mb-4 text-emerald-400 uppercase tracking-wider text-center">Ingest Intel (txt)</h2>
            <input 
              type="file" 
              accept=".txt" 
              onChange={(e) => setUploadFile(e.target.files[0])}
              className="mb-6 block w-full text-sm text-slate-300
                file:mr-4 file:py-2 file:px-4
                file:rounded file:border-0
                file:text-sm file:font-bold file:uppercase file:tracking-wider
                file:bg-emerald-600 file:text-white
                hover:file:bg-emerald-500 cursor-pointer transition-colors"
            />
            <div className="flex justify-end space-x-3">
              <button 
                onClick={() => setShowUpload(false)}
                className="px-4 py-2 border border-slate-700 rounded text-slate-400 hover:bg-slate-800 transition-colors font-semibold uppercase text-xs tracking-wider"
              >
                Cancel
              </button>
              <button 
                onClick={handleUploadClick}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded font-bold transition-colors shadow-lg uppercase text-xs tracking-wider"
              >
                Launch NLP Engine
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
