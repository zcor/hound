'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { getProjectSessions, type Session } from '@/lib/api';

export default function ProjectSessionsPage() {
  const params = useParams();
  const projectId = Number(params.id);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchSessions = async () => {
      try {
        const data = await getProjectSessions(projectId);
        setSessions(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch sessions');
      } finally {
        setLoading(false);
      }
    };

    if (projectId) {
      fetchSessions();
    }
  }, [projectId]);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-lg">Loading sessions...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-lg text-red-600">Error: {error}</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-zinc-900">
      <div className="container mx-auto px-4 py-8">
        <div className="mb-8">
          <Link
            href="/projects"
            className="mb-4 inline-block text-blue-600 hover:text-blue-800 dark:text-blue-400"
          >
            ← Back to Projects
          </Link>
          <h1 className="text-3xl font-bold text-zinc-900 dark:text-zinc-50">
            Audit Sessions
          </h1>
          <p className="mt-2 text-zinc-600 dark:text-zinc-400">
            View audit sessions for project #{projectId}
          </p>
        </div>

        {sessions.length === 0 ? (
          <div className="rounded-lg bg-white p-8 text-center dark:bg-zinc-800">
            <p className="text-zinc-600 dark:text-zinc-400">
              No sessions found for this project.
            </p>
          </div>
        ) : (
          <div className="overflow-hidden rounded-lg bg-white shadow dark:bg-zinc-800">
            <table className="min-w-full divide-y divide-zinc-200 dark:divide-zinc-700">
              <thead className="bg-zinc-50 dark:bg-zinc-900">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                    Session ID
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                    Start Time
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                    Investigations
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-200 bg-white dark:divide-zinc-700 dark:bg-zinc-800">
                {sessions.map((session) => (
                  <tr key={session.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-700/50">
                    <td className="whitespace-nowrap px-6 py-4 text-sm font-medium text-zinc-900 dark:text-zinc-50">
                      {session.session_id}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4">
                      <span
                        className={`inline-flex rounded-full px-2 text-xs font-semibold leading-5 ${
                          session.status === 'completed'
                            ? 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400'
                            : session.status === 'active'
                            ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400'
                            : 'bg-zinc-100 text-zinc-800 dark:bg-zinc-900/20 dark:text-zinc-400'
                        }`}
                      >
                        {session.status}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 text-sm text-zinc-500 dark:text-zinc-400">
                      {new Date(session.start_time).toLocaleString()}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 text-sm text-zinc-500 dark:text-zinc-400">
                      {session.investigations_count}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 text-sm font-medium">
                      <Link
                        href={`/projects/${projectId}/audit/${session.session_id}`}
                        className="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300"
                      >
                        View Audit
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
