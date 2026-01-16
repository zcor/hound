'use client';

import { useEffect, useState } from 'react';
import ReactFlow, {
  Node,
  Edge,
  Controls,
  Background,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { getSessionGraph, type GraphData } from '@/lib/api';

interface GraphPanelProps {
  sessionId: string;
}

export default function GraphPanel({ sessionId }: GraphPanelProps) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  useEffect(() => {
    const fetchGraph = async () => {
      try {
        const data = await getSessionGraph(sessionId);
        
        // Transform graph data to ReactFlow format
        const flowNodes: Node[] = (data.nodes || []).map((node, index) => ({
          id: node.id || `node-${index}`,
          data: { 
            label: node.label || node.id || `Node ${index}`,
            ...node,
          },
          position: { 
            x: Math.random() * 500, 
            y: Math.random() * 500 
          },
          type: 'default',
        }));

        const flowEdges: Edge[] = (data.edges || []).map((edge, index) => ({
          id: `edge-${index}`,
          source: edge.source,
          target: edge.target,
          label: edge.label,
          markerEnd: {
            type: MarkerType.ArrowClosed,
          },
        }));

        setNodes(flowNodes);
        setEdges(flowEdges);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch graph');
      } finally {
        setLoading(false);
      }
    };

    fetchGraph();
  }, [sessionId, setNodes, setEdges]);

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center rounded-lg bg-white dark:bg-zinc-800">
        <div className="text-zinc-600 dark:text-zinc-400">Loading graph...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex h-full items-center justify-center rounded-lg bg-white dark:bg-zinc-800">
        <div className="text-red-600">Error: {error}</div>
      </div>
    );
  }

  return (
    <div className="h-full overflow-hidden rounded-lg bg-white dark:bg-zinc-800">
      <div className="border-b border-zinc-200 p-4 dark:border-zinc-700">
        <h2 className="text-lg font-semibold text-zinc-900 dark:text-zinc-50">
          System Graph
        </h2>
      </div>
      <div className="h-[calc(100%-4rem)]">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          fitView
          className="bg-zinc-50 dark:bg-zinc-900"
        >
          <Background />
          <Controls />
          <MiniMap 
            nodeColor={(node) => {
              return '#3b82f6';
            }}
            className="!bg-zinc-100 dark:!bg-zinc-800"
          />
        </ReactFlow>
      </div>
    </div>
  );
}
