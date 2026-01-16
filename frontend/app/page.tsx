import Link from 'next/link';

export default function Home() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-zinc-50 dark:bg-zinc-900">
      <main className="flex w-full max-w-4xl flex-col items-center gap-8 p-8">
        <h1 className="text-4xl font-bold text-zinc-900 dark:text-zinc-50">
          Hound Dashboard
        </h1>
        <p className="text-lg text-zinc-600 dark:text-zinc-400">
          Professional SaaS dashboard for security auditing
        </p>
        <div className="flex gap-4">
          <Link
            href="/projects"
            className="rounded-lg bg-blue-600 px-6 py-3 text-white transition-colors hover:bg-blue-700"
          >
            View Projects
          </Link>
        </div>
      </main>
    </div>
  );
}
