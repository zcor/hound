/**
 * Authentication utilities for GitHub OAuth and JWT token management
 */

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

/**
 * Initiate GitHub OAuth login flow
 */
export async function loginWithGitHub(): Promise<void> {
  try {
    const response = await fetch(`${API_BASE_URL}/auth/github/login`);
    const { url } = await response.json();
    
    if (typeof window !== 'undefined') {
      window.location.href = url;
    }
  } catch (error) {
    console.error('Failed to initiate GitHub login:', error);
    throw error;
  }
}

/**
 * Handle GitHub OAuth callback and store tokens
 */
export async function handleGitHubCallback(code: string): Promise<{
  access_token: string;
  user: {
    id: number;
    github_login: string;
    email: string | null;
    name: string | null;
    avatar_url: string | null;
  };
  tenant_id: number;
}> {
  try {
    const response = await fetch(`${API_BASE_URL}/auth/github/callback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    });

    if (!response.ok) {
      throw new Error('GitHub authentication failed');
    }

    const data = await response.json();

    // Store token and tenant_id in localStorage
    if (typeof window !== 'undefined') {
      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('tenant_id', data.tenant_id.toString());
      localStorage.setItem('user', JSON.stringify(data.user));
    }

    return data;
  } catch (error) {
    console.error('Failed to complete GitHub authentication:', error);
    throw error;
  }
}

/**
 * Get current user info from JWT token
 */
export async function getCurrentUser(): Promise<{
  id: number;
  github_login: string;
  email: string | null;
  name: string | null;
  avatar_url: string | null;
  tenant_id: number;
} | null> {
  const token = typeof window !== 'undefined' ? localStorage.getItem('access_token') : null;
  
  if (!token) {
    return null;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/auth/me`, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      // Token is invalid or expired
      logout();
      return null;
    }

    return await response.json();
  } catch (error) {
    console.error('Failed to get current user:', error);
    logout();
    return null;
  }
}

/**
 * Get stored access token
 */
export function getAccessToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('access_token');
}

/**
 * Get stored tenant ID
 */
export function getTenantId(): number | null {
  if (typeof window === 'undefined') return null;
  const stored = localStorage.getItem('tenant_id');
  return stored ? parseInt(stored, 10) : null;
}

/**
 * Check if user is authenticated
 */
export function isAuthenticated(): boolean {
  if (typeof window === 'undefined') return false;
  return !!localStorage.getItem('access_token');
}

/**
 * Logout user and clear stored tokens
 */
export function logout(): void {
  if (typeof window === 'undefined') return;
  
  localStorage.removeItem('access_token');
  localStorage.removeItem('tenant_id');
  localStorage.removeItem('user');
  
  window.location.href = '/login';
}
