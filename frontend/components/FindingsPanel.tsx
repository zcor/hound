'use client';

import { useEffect, useState } from 'react';
import { getSessionFindings, updateFindingStatus, type Finding } from '@/lib/api';

interface FindingsPanelProps {
  sessionId: string;
}

export default function FindingsPanel({ sessionId }: FindingsPanelProps) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [updatingId, setUpdatingId] = useState<number | null>(null);

  const fetchFindings = async () => {
    try {
      const data = await getSessionFindings(sessionId);
      setFindings(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch findings');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [sessionId]);

  const handleStatusUpdate = async (findingId: number, newStatus: string) => {
    setUpdatingId(findingId);
    try {
      await updateFindingStatus(findingId, newStatus);
      // Update local state
      setFindings((prev) =>
        prev.map((f) => (f.id === findingId ? { ...f, status: newStatus } : f))
      );
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to update status');
    } finally {
      setUpdatingId(null);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400';
      case 'high':
        return 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-400';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400';
      case 'low':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400';
      default:
        return 'bg-zinc-100 text-zinc-800 dark:bg-zinc-900/20 dark:text-zinc-400';
    }
  };

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center rounded-lg bg-white dark:bg-zinc-800">
        <div className="text-zinc-600 dark:text-zinc-400">Loading findings...</div>
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
    <div className="flex h-full flex-col overflow-hidden rounded-lg bg-white dark:bg-zinc-800">
      <div className="border-b border-zinc-200 p-4 dark:border-zinc-700">
        <h2 className="text-lg font-semibold text-zinc-900 dark:text-zinc-50">
          Findings ({findings.length})
        </h2>
      </div>
      <div className="flex-1 overflow-y-auto p-4">
        {findings.length === 0 ? (
          <div className="flex h-full items-center justify-center text-zinc-500 dark:text-zinc-400">
            No confirmed findings yet
          </div>
        ) : (
          <div className="space-y-4">
            {findings.map((finding) => (
              <div
                key={finding.id}
                className="rounded-lg border border-zinc-200 bg-white p-4 dark:border-zinc-700 dark:bg-zinc-900"
              >
                <div className="mb-2 flex items-start justify-between">
                  <div className="flex-1">
                    <h3 className="font-semibold text-zinc-900 dark:text-zinc-50">
                      {finding.title}
                    </h3>
                    <div className="mt-1 flex items-center gap-2">
                      <span
                        className={`inline-flex rounded-full px-2 py-1 text-xs font-semibold ${getSeverityColor(
                          finding.severity
                        )}`}
                      >
                        {finding.severity}
                      </span>
                      <span className="text-xs text-zinc-500 dark:text-zinc-400">
                        {finding.vulnerability_type}
                      </span>
                      <span className="text-xs text-zinc-500 dark:text-zinc-400">
                        Confidence: {(finding.confidence * 100).toFixed(0)}%
                      </span>
                    </div>
                  </div>
                </div>
                <p className="mb-3 text-sm text-zinc-600 dark:text-zinc-400">
                  {finding.description}
                </p>
                {finding.node_refs && finding.node_refs.length > 0 && (
                  <div className="mb-3">
                    <div className="text-xs font-medium text-zinc-500 dark:text-zinc-400">
                      References:
                    </div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {finding.node_refs.map((ref, idx) => (
                        <span
                          key={idx}
                          className="rounded bg-zinc-100 px-2 py-1 text-xs text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
                        >
                          {ref}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                <div className="flex gap-2">
                  <button
                    onClick={() => handleStatusUpdate(finding.id, 'confirmed')}
                    disabled={updatingId === finding.id || finding.status === 'confirmed'}
                    className="rounded bg-green-600 px-3 py-1 text-sm text-white transition-colors hover:bg-green-700 disabled:bg-zinc-400 disabled:cursor-not-allowed"
                  >
                    {finding.status === 'confirmed' ? '✓ Confirmed' : 'Confirm'}
                  </button>
                  <button
                    onClick={() => handleStatusUpdate(finding.id, 'rejected')}
                    disabled={updatingId === finding.id || finding.status === 'rejected'}
                    className="rounded bg-red-600 px-3 py-1 text-sm text-white transition-colors hover:bg-red-700 disabled:bg-zinc-400 disabled:cursor-not-allowed"
                  >
                    {finding.status === 'rejected' ? '✗ Rejected' : 'Reject'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
