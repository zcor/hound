#!/bin/bash

echo "🚀 Starting Firepan Development Environment"
echo "==========================================="

# Check if database exists
if [ ! -f "hound.db" ]; then
    echo "Database not found. Creating..."
    python scripts/seed_test_data.py
fi

# Start API server
echo ""
echo "Starting Hound API on port 8000..."
echo "API Docs: http://localhost:8000/docs"
echo ""

uvicorn server.api:app --reload --host 0.0.0.0 --port 8000
