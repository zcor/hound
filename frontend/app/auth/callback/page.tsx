'use client';

import { Suspense, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { handleGitHubCallback } from '@/lib/auth';

function AuthCallbackLoading() {
  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-900">
      <div className="bg-gray-800 p-8 rounded-lg shadow-lg max-w-md w-full text-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
        <h1 className="text-2xl font-bold text-white mb-2">Completing Sign In</h1>
        <p className="text-gray-400">Please wait while we authenticate you...</p>
      </div>
    </div>
  );
}

export default function AuthCallbackPage() {
  return (
    <Suspense fallback={<AuthCallbackLoading />}>
      <AuthCallbackInner />
    </Suspense>
  );
}

function AuthCallbackInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const code = searchParams.get('code');
    const errorParam = searchParams.get('error');

    if (errorParam) {
      setError('GitHub authentication was cancelled or failed');
      setTimeout(() => router.push('/login'), 3000);
      return;
    }

    if (!code) {
      setError('No authorization code received');
      setTimeout(() => router.push('/login'), 3000);
      return;
    }

    // Handle the OAuth callback
    handleGitHubCallback(code)
      .then(() => {
        // Successfully authenticated, redirect to home
        router.push('/');
      })
      .catch((err) => {
        console.error('Authentication failed:', err);
        setError(err?.message || 'Authentication failed. Please try again.');
        setTimeout(() => router.push('/login'), 3000);
      });
  }, [searchParams, router]);

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-900">
        <div className="bg-gray-800 p-8 rounded-lg shadow-lg max-w-md w-full text-center">
          <div className="text-red-500 text-5xl mb-4">✗</div>
          <h1 className="text-2xl font-bold text-white mb-2">Authentication Failed</h1>
          <p className="text-gray-400 mb-4">{error}</p>
          <p className="text-sm text-gray-500">Redirecting to login...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-900">
      <div className="bg-gray-800 p-8 rounded-lg shadow-lg max-w-md w-full text-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
        <h1 className="text-2xl font-bold text-white mb-2">Completing Sign In</h1>
        <p className="text-gray-400">Please wait while we authenticate you...</p>
      </div>
    </div>
  );
}
