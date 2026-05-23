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
                      <div className="flex flex-col gap-1">
                        {/* primary status pill */}
                        <span
                          className={`inline-flex rounded-full px-2 text-xs font-semibold leading-5 ${
                            session.status === 'completed'
                              ? 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400'
                              : session.status === 'active'
                              ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400'
                              : session.status === 'awaiting_curation'
                              ? 'bg-amber-100 text-amber-800 dark:bg-amber-900/20 dark:text-amber-400'
                              : 'bg-zinc-100 text-zinc-800 dark:bg-zinc-900/20 dark:text-zinc-400'
                          }`}
                        >
                          {session.status}
                        </span>
                        {/* firepan-y22: coverage badge — show "Partial — 67%" when
                            coverage_ratio < 1.0; hide when null (engagement didn't
                            track) or 1.0 (clean) */}
                        {typeof session.coverage_ratio === 'number' && session.coverage_ratio < 1.0 && (
                          <span
                            className="inline-flex rounded-full bg-orange-100 px-2 text-xs font-semibold leading-5 text-orange-800 dark:bg-orange-900/20 dark:text-orange-400"
                            title="Audit terminated before all chunks were processed. Findings are based on a partial run."
                          >
                            Partial — {Math.round(session.coverage_ratio * 100)}%
                          </span>
                        )}
                        {/* firepan-y22: curator warning — fire when audit_context
                            was provided but curator did not apply. Loud color
                            because shipping un-curated findings on a scoped
                            engagement misrepresents what was audited. */}
                        {session.curator_applied === false && (
                          <span
                            className="inline-flex rounded-full bg-red-100 px-2 text-xs font-semibold leading-5 text-red-800 dark:bg-red-900/20 dark:text-red-400"
                            title="audit_context.scope_files was provided on dispatch but the firepan-curator did not run. Findings may include out-of-scope items and severity-inflated entries."
                          >
                            ⚠ uncurated
                          </span>
                        )}
                        {/* firepan-y22 + firepan-a1: bump-verify verdict pill.
                            Verdict vocab: 'verified' / 'verified_fragile' /
                            'unverified' / 'disproved' (Phase 4 axes), or
                            'mve_verified' / 'mve_unverified' / 'mve_aborted_cost'
                            (Phase 3 A1 MVE loop). */}
                        {session.bump_verify_verdict && (
                          <span
                            className={`inline-flex rounded-full px-2 text-xs font-semibold leading-5 ${
                              session.bump_verify_verdict === 'verified' || session.bump_verify_verdict === 'mve_verified'
                                ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/20 dark:text-emerald-400'
                                : session.bump_verify_verdict === 'verified_fragile'
                                ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400'
                                : session.bump_verify_verdict === 'mve_aborted_cost'
                                ? 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-400'
                                : 'bg-zinc-100 text-zinc-700 dark:bg-zinc-900/20 dark:text-zinc-400'
                            }`}
                            title={`firepan-bump-verify verdict: ${session.bump_verify_verdict}`}
                          >
                            verify: {session.bump_verify_verdict}
                          </span>
                        )}
                        {/* firepan-a1: USD impact + cost pills when the A1
                            MVE loop ran. impact_usd is the mid bound from
                            Phase 5 (revenue normalizer); cost_usd is the
                            cumulative Claude + RPC spend. */}
                        {typeof session.bump_verify_impact_usd === 'number' && session.bump_verify_impact_usd > 0 && (
                          <span
                            className="inline-flex rounded-full bg-rose-100 px-2 text-xs font-semibold leading-5 text-rose-800 dark:bg-rose-900/20 dark:text-rose-400"
                            title="Bounded USD impact of the verified exploit (A1 revenue normalizer)"
                          >
                            ${Math.round(session.bump_verify_impact_usd).toLocaleString()} impact
                          </span>
                        )}
                        {typeof session.bump_verify_cost_usd === 'number' && session.bump_verify_cost_usd > 0 && (
                          <span
                            className="inline-flex rounded-full bg-zinc-100 px-2 text-xs font-medium leading-5 text-zinc-700 dark:bg-zinc-900/20 dark:text-zinc-400"
                            title={`Verify-mode spend: $${session.bump_verify_cost_usd.toFixed(2)}${session.bump_verify_iterations_used ? ` (${session.bump_verify_iterations_used} iters)` : ''}`}
                          >
                            ${session.bump_verify_cost_usd.toFixed(2)}
                          </span>
                        )}
                      </div>
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
