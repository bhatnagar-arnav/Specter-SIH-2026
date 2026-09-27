import React, { useState, useEffect, useRef } from 'react';
import { Network } from 'vis-network';

function NetworkGraph({ data, onNodeClick }) {
  const container = useRef(null);
  const network = useRef(null);
  const [selectedEntity, setSelectedEntity] = useState(null);

  useEffect(() => {
    if (container.current && data) {
      const visNodes = data.nodes.map(node => {
        // 1. Base Node Setup
        let shape = 'box';
        let backgroundColor = '#3b82f6'; // Default Blue
        let shadowColor = '#3b82f6';
        let labelText = node.name || node.label || node.id;
        let fontColor = '#000000'; // Black text for readability

        // 2. Assign Symbols and Colors based on Entity Label/Type
        let originalName = node.name || node.label || node.id;
        let cleanName = originalName.replace(/^(BTC|XMR|ETH):/, '');
        
        if (node.label === 'Crypto_Wallet') {
            if (cleanName.startsWith('1') || cleanName.startsWith('3') || cleanName.startsWith('bc1')) {
                labelText = '₿ Bitcoin Wallet';
            } else if (cleanName.startsWith('4') || cleanName.startsWith('8')) {
                labelText = 'ɱ Monero Wallet';
            } else {
                labelText = '💰 Crypto Wallet';
            }
            backgroundColor = '#10b981'; // Emerald Green
            shadowColor = '#10b981';
        } else if (node.label === 'IP_Address') {
            labelText = '🌐 ' + labelText;
            backgroundColor = '#10b981';
            shadowColor = '#10b981';
        } else if (node.label === 'Onion_Domain' || node.label === 'PGP_Key') {
            backgroundColor = '#10b981';
            shadowColor = '#10b981';
        } else if (node.label === 'Linguistic_Marker') {
            labelText = '💬 ' + labelText;
            backgroundColor = '#f59e0b'; // Amber/Yellow
            shadowColor = '#f59e0b';
            shape = 'diamond';
        } else if (labelText.startsWith('INTEL_') || node.label === 'Intel_Report') {
            // Intel Documents
            labelText = '📄 ' + labelText;
            backgroundColor = '#64748b'; // Slate
            shadowColor = '#000000'; // No glow for reports
        } else {
            // Threat Actors
            labelText = '👤 ' + labelText;
        }

        // 3. NEXUS OVERRIDE (High Centrality)
        const centralityScore = node.metrics?.betweenness_centrality || 0;
        const isNexus = (centralityScore > 0.4) && (node.label !== 'Intel_Report'); // Threshold for Nexus, excluding Documents

        if (isNexus) {
            shape = 'circle';
            backgroundColor = '#f43f5e'; // Rose Red
            shadowColor = '#f43f5e';
        }

        // 4. Return formatting to vis.js
        return {
            id: node.id,
            label: labelText,
            shape: shape,
            color: {
                background: backgroundColor,
                border: '#1e293b',
                highlight: { background: '#ffffff', border: backgroundColor }
            },
            font: { 
                color: fontColor, 
                face: 'Inter, sans-serif',
                size: 14,
                bold: isNexus // Make Nexus text bold
            },
            shadow: {
                enabled: true,
                color: shadowColor,
                size: isNexus ? 25 : 10, // Massive neon glow for Nexus, subtle glow for others
                x: 0,
                y: 0
            },
            title: `Name: ${originalName}\nBetweenness Centrality: ${centralityScore}\nRisk Tier: ${node.risk_tier || 'LOW'}` // Tooltip data
        };
      });

      const visData = {
        nodes: visNodes,
        edges: data.edges.map(edge => ({ ...edge, font: { align: 'middle' } }))
      };

      const options = {
        nodes: {
            font: {
                face: "'Inter', 'Segoe UI', Roboto, sans-serif", // Clean, modern font
                size: 15,
                color: '#000000', // Keeps text highly readable inside the colored boxes
                vadjust: 1
            },
            borderWidth: 0, // Removes messy borders around the nodes
        },
        edges: {
            font: {
                face: "'Inter', 'Segoe UI', Roboto, sans-serif",
                size: 12,
                color: '#00ADB5', // Teal text for relationship labels
                strokeWidth: 4,   // Creates a smooth cutout effect
                strokeColor: '#222831', // Matches the graph's Deep Slate background perfectly
                align: 'middle'
            },
            color: {
                color: '#393E46', // Dark gray lines (subtle, doesn't clash with neon nodes)
                highlight: '#00ADB5'
            },
            smooth: {
                type: 'continuous',
                roundness: 0.5
            },
            arrows: {
                to: { enabled: true, scaleFactor: 0.6 }
            }
        },
        layout: {
            improvedLayout: true,
            hierarchical: false
        },
        physics: {
            enabled: true,
            solver: 'barnesHut',
            barnesHut: {
                gravitationalConstant: -4000, // Strong negative gravity pushes nodes away from each other
                centralGravity: 0.1,          // Lower central gravity stops them from pulling into a tight middle ball
                springLength: 250,            // Increases the minimum length of the relationship edges
                springConstant: 0.04,
                damping: 0.09                 // Prevents the graph from jittering infinitely
            },
            stabilization: {
                enabled: true,
                iterations: 150,              // Pre-calculates the layout so it loads cleanly 
                updateInterval: 25
            }
        },
        interaction: {
            hover: true,
            dragNodes: true,
            dragView: true,
            zoomView: true,
            tooltipDelay: 200,
            navigationButtons: true,          // Adds zoom/pan controls to the canvas
            keyboard: true
        }
      };

      network.current = new Network(container.current, visData, options);

      network.current.on('click', (params) => {
        if (params.nodes.length > 0) {
          const nodeId = params.nodes[0];
          const node = data.nodes.find(n => n.id === nodeId);
          if (node) {
            setSelectedEntity(node);
            if (onNodeClick) onNodeClick(node);
          }
        } else {
          setSelectedEntity(null);
        }
      });
    }

    return () => {
      if (network.current) {
        network.current.destroy();
      }
    };
  }, [data, onNodeClick]);

  return (
    <div style={{ position: 'relative', height: '100%', width: '100%', minHeight: '350px' }}>
      <div ref={container} style={{ height: '100%', width: '100%' }} className="bg-transparent" />
      
      {selectedEntity && (
        <div className="absolute top-4 right-4 z-50 w-80 bg-slate-900 border border-slate-700 shadow-2xl rounded-lg overflow-hidden flex flex-col">
          <div className="flex justify-between items-center bg-slate-800 px-4 py-3 border-b border-slate-700">
            <h4 className="text-emerald-400 font-bold uppercase text-xs tracking-wider">
              {selectedEntity.label || "Entity Details"}
            </h4>
            <button 
              onClick={() => setSelectedEntity(null)} 
              className="text-slate-400 hover:text-rose-400 transition-colors p-1 flex items-center justify-center font-bold"
              title="Close Panel"
            >
              ✕
            </button>
          </div>
          <div className="p-4 flex flex-col gap-3">
            <div>
              <span className="block text-[10px] text-slate-500 uppercase tracking-wider mb-1 font-semibold">Raw Identifier</span>
              <div className="bg-slate-950 p-3 rounded-md border border-slate-800 text-slate-300 font-mono text-sm break-all shadow-inner">
                {selectedEntity.name || selectedEntity.id}
              </div>
            </div>
            
            {(selectedEntity.metrics?.betweenness_centrality !== undefined) && (
              <div className="grid grid-cols-2 gap-3 mt-1">
                <div className="bg-slate-800/50 p-2.5 rounded border border-slate-800 flex flex-col items-center">
                  <span className="block text-[10px] text-slate-500 uppercase tracking-wider mb-1">Centrality</span>
                  <span className="text-slate-200 font-semibold">{parseFloat(selectedEntity.metrics.betweenness_centrality).toFixed(3)}</span>
                </div>
                <div className="bg-slate-800/50 p-2.5 rounded border border-slate-800 flex flex-col items-center">
                  <span className="block text-[10px] text-slate-500 uppercase tracking-wider mb-1">Risk Tier</span>
                  <span className={`font-bold ${selectedEntity.risk_tier === 'HIGH' ? 'text-rose-400' : 'text-emerald-400'}`}>
                    {selectedEntity.risk_tier || 'LOW'}
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default NetworkGraph;
