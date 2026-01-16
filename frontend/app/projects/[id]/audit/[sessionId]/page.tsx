'use client';

import { useParams } from 'next/navigation';
import Link from 'next/link';
import ActivityPanel from '@/components/ActivityPanel';
import GraphPanel from '@/components/GraphPanel';
import FindingsPanel from '@/components/FindingsPanel';

export default function AuditViewPage() {
  const params = useParams();
  const projectId = params.id as string;
  const sessionId = params.sessionId as string;

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-zinc-900">
      <div className="container mx-auto px-4 py-4">
        <div className="mb-4">
          <Link
            href={`/projects/${projectId}`}
            className="inline-block text-blue-600 hover:text-blue-800 dark:text-blue-400"
          >
            ← Back to Sessions
          </Link>
          <h1 className="mt-2 text-2xl font-bold text-zinc-900 dark:text-zinc-50">
            Audit View
          </h1>
          <p className="text-sm text-zinc-600 dark:text-zinc-400">
            Session: {sessionId}
          </p>
        </div>

        {/* Three-panel layout */}
        <div className="grid h-[calc(100vh-12rem)] grid-cols-12 gap-4">
          {/* Left Panel - Activity */}
          <div className="col-span-12 lg:col-span-3">
            <ActivityPanel sessionId={sessionId} />
          </div>

          {/* Center Panel - Graph */}
          <div className="col-span-12 lg:col-span-6">
            <GraphPanel sessionId={sessionId} />
          </div>

          {/* Right Panel - Findings */}
          <div className="col-span-12 lg:col-span-3">
            <FindingsPanel sessionId={sessionId} />
          </div>
        </div>
      </div>
    </div>
  );
}
