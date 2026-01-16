# Hound Dashboard - Frontend

Professional SaaS dashboard for Hound security analysis.

## Overview

This Next.js application provides a modern web interface for managing Hound security audit projects, viewing audit sessions, and analyzing findings.

## Features

- **Project List**: Browse all security audit projects with statistics
- **Audit View**: Comprehensive three-panel layout for audit analysis
  - **Left Panel**: Live activity log with WebSocket updates
  - **Center Panel**: Interactive graph visualization using ReactFlow
  - **Right Panel**: Findings cards with confirm/reject actions

## Prerequisites

- Node.js 18+ 
- npm or yarn
- Hound API server running (see [server/README.md](../server/README.md))

## Installation

1. Install dependencies:
```bash
cd frontend
npm install
```

2. Configure the API URL:
```bash
cp .env.local.example .env.local
# Edit .env.local to point to your Hound API server
```

## Development

Run the development server:

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

## Production Build

Build the application:

```bash
npm run build
```

Start the production server:

```bash
npm start
```

## Project Structure

```
frontend/
├── app/                      # Next.js app directory
│   ├── page.tsx             # Home page
│   ├── projects/            # Projects pages
│   │   ├── page.tsx         # Project list
│   │   └── [id]/            # Project detail
│   │       ├── page.tsx     # Sessions list
│   │       └── audit/       # Audit view
│   │           └── [sessionId]/
│   │               └── page.tsx  # Audit dashboard
│   ├── layout.tsx           # Root layout
│   └── globals.css          # Global styles
├── components/              # React components
│   ├── ActivityPanel.tsx    # Live activity log
│   ├── GraphPanel.tsx       # Graph visualization
│   └── FindingsPanel.tsx    # Findings list
├── lib/                     # Utilities
│   └── api.ts              # API client
└── public/                  # Static files
```

## API Integration

The frontend communicates with the Hound API server through the following endpoints:

- `GET /projects` - List all projects
- `GET /projects/{id}/sessions` - List project sessions
- `GET /sessions/{id}/graph` - Get graph visualization data
- `GET /sessions/{id}/findings` - Get session findings
- `POST /findings/{id}/status` - Update finding status
- `WS /ws/sessions/{id}` - WebSocket for live updates

## Environment Variables

- `NEXT_PUBLIC_API_URL` - Hound API server URL (default: http://localhost:8000)

## Tech Stack

- **Framework**: Next.js 16 with App Router
- **Language**: TypeScript
- **Styling**: Tailwind CSS 4
- **Graph Visualization**: ReactFlow
- **HTTP Client**: Axios
- **Real-time**: WebSocket API

## Development Tips

- The app uses Next.js App Router (app directory)
- All pages are client-side rendered (`'use client'`) for interactivity
- WebSocket connections auto-reconnect on disconnection
- Graph layout uses automatic positioning - can be customized in GraphPanel.tsx

## Troubleshooting

### API Connection Issues

If you see "Failed to fetch" errors:
1. Ensure the Hound API server is running (`python server/start.py`)
2. Check that `NEXT_PUBLIC_API_URL` in `.env.local` is correct
3. Verify CORS is configured in the API server

### WebSocket Connection Failed

If activity logs don't update:
1. Check browser console for WebSocket errors
2. Ensure the API server WebSocket endpoint is accessible
3. Check firewall/proxy settings

### Graph Not Displaying

If the graph doesn't render:
1. Verify the session has graph data (`GET /sessions/{id}/graph`)
2. Check browser console for ReactFlow errors
3. Ensure the graph data format matches expected schema

## License

Apache 2.0 - See LICENSE.txt in the root directory

