/**
 * API client for Hound backend
 */
import axios, { AxiosInstance } from 'axios';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// Helper functions for authentication
export function getAccessToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('access_token');
}

export function getTenantId(): number | null {
  if (typeof window === 'undefined') return null;
  const stored = localStorage.getItem('tenant_id');
  return stored ? parseInt(stored, 10) : null;
}

// Create axios instance with auth interceptors
const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth token to every request
apiClient.interceptors.request.use((config) => {
  const token = getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle 401 unauthorized
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Redirect to login on unauthorized
      if (typeof window !== 'undefined') {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

export const api = apiClient;

// Types
export interface Project {
  id: number;
  name: string;
  source_path: string | null;
  git_url: string | null;
  description: string | null;
  status: string;
  created_at: string;
  last_accessed: string;
  graphs_count: number;
  sessions_count: number;
  hypotheses_count: number;
  confirmed_count: number;
}

export interface Session {
  id: number;
  session_id: string;
  status: string;
  start_time: string;
  end_time: string | null;
  models: Record<string, any> | null;
  token_usage: Record<string, any> | null;
  coverage: Record<string, any> | null;
  investigations_count: number;
  // firepan-y22: curator + bump-verify state surfaced on /projects/{id}/sessions
  // so the dashboard can render coverage / curator-applied / verify-verdict
  // banners inline. Null when the engagement didn't use the curator or verify mode.
  curator_applied: boolean | null;
  curator_summary: Record<string, number> | null;
  coverage_ratio: number | null;
  bump_verify_verdict: string | null;
  // firepan-a1 — Bump-verify A1 cherry-pick state surfaced for dashboard.
  bump_verify_cost_usd: number | null;
  bump_verify_iterations_used: number | null;
  bump_verify_impact_usd: number | null;
}

export interface Finding {
  id: number;
  hypothesis_id: string;
  title: string;
  description: string;
  vulnerability_type: string;
  status: string;
  confidence: number;
  severity: string;
  node_refs: string[] | null;
  evidence: Record<string, any> | null;
  reported_by_model: string | null;
  junior_model: string | null;
  senior_model: string | null;
  created_at: string;
  updated_at: string;
}

export interface GraphNode {
  id: string;
  label?: string;
  type?: string;
  [key: string]: any;
}

export interface GraphEdge {
  source: string;
  target: string;
  label?: string;
  [key: string]: any;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  [key: string]: any;
}

// API functions
export const getProjects = async (): Promise<Project[]> => {
  const response = await api.get<Project[]>('/projects');
  return response.data;
};

export const getProjectSessions = async (projectId: number): Promise<Session[]> => {
  const response = await api.get<Session[]>(`/projects/${projectId}/sessions`);
  return response.data;
};

export const getSessionGraph = async (sessionId: string): Promise<GraphData> => {
  const response = await api.get<GraphData>(`/sessions/${sessionId}/graph`);
  return response.data;
};

export const getSessionFindings = async (sessionId: string): Promise<Finding[]> => {
  const response = await api.get<Finding[]>(`/sessions/${sessionId}/findings`);
  return response.data;
};

export const updateFindingStatus = async (
  findingId: number,
  status: string
): Promise<{ id: number; hypothesis_id: string; status: string; updated_at: string }> => {
  const response = await api.post(`/findings/${findingId}/status`, { status });
  return response.data;
};

// WebSocket URL helper
export const getWebSocketUrl = (sessionId: string): string => {
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsHost = API_BASE_URL.replace(/^https?:\/\//, '');
  return `${wsProtocol}//${wsHost}/ws/sessions/${sessionId}`;
};
